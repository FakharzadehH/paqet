package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type SendHandle struct {
	handles       []*pcap.Handle
	handleIdx     atomic.Uint64
	srcIPv4       net.IP
	srcIPv4RHWA   net.HardwareAddr
	srcIPv6       net.IP
	srcIPv6RHWA   net.HardwareAddr
	srcPort       uint16
	time          uint32
	tsCounter     uint32
	dscp          atomic.Int32
	dscpSet       atomic.Bool
	computeChecks bool
	tcpF          TCPF
	ethPool       sync.Pool
	ipv4Pool      sync.Pool
	ipv6Pool      sync.Pool
	tcpPool       sync.Pool
	bufPool       sync.Pool
	tsDataPool    sync.Pool // Pool for 8-byte timestamp data
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	// Create pool of pcap handles - one per CPU core (minimum 2)
	numHandles := runtime.NumCPU()
	if numHandles < 2 {
		numHandles = 2
	}
	
	handles := make([]*pcap.Handle, numHandles)
	for i := 0; i < numHandles; i++ {
		handle, err := newHandle(cfg)
		if err != nil {
			// Clean up any handles we've already created
			for j := 0; j < i; j++ {
				handles[j].Close()
			}
			return nil, fmt.Errorf("failed to open pcap handle %d: %w", i, err)
		}

		// SetDirection is not fully supported on Windows Npcap, so skip it
		if runtime.GOOS != "windows" {
			if err := handle.SetDirection(pcap.DirectionOut); err != nil {
				// Clean up all handles on error
				handle.Close()
				for j := 0; j < i; j++ {
					handles[j].Close()
				}
				return nil, fmt.Errorf("failed to set pcap direction out on handle %d: %v", i, err)
			}
		}
		handles[i] = handle
	}

	sh := &SendHandle{
		handles:       handles,
		srcPort:       uint16(cfg.Port),
		computeChecks: cfg.PCAP.Checksums,
		tcpF:          TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:          uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
		tsDataPool: sync.Pool{
			New: func() any {
				b := make([]byte, 8)
				return &b
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	var tos uint8
	if h.dscpSet.Load() {
		// DSCP was explicitly set, use it (DSCP is upper 6 bits of TOS field)
		tos = uint8(h.dscp.Load()) << 2
	} else {
		// DSCP not set, use default value for backward compatibility
		tos = 184
	}
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      tos,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	var trafficClass uint8
	if h.dscpSet.Load() {
		// DSCP was explicitly set, use it (DSCP is upper 6 bits)
		trafficClass = uint8(h.dscp.Load()) << 2
	} else {
		// DSCP not set, use default value for backward compatibility
		trafficClass = 184
	}
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: trafficClass,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		// Get timestamp data from pool
		tsDataPtr := h.tsDataPool.Get().(*[]byte)
		tsData := *tsDataPtr
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], 0)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		}
		// Return to pool after use (when TCP layer is returned)
		defer h.tsDataPool.Put(tsDataPtr)
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		// Get timestamp data from pool
		tsDataPtr := h.tsDataPool.Get().(*[]byte)
		tsData := *tsDataPtr
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], tsEcr)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData},
		}
		// Return to pool after use (when TCP layer is returned)
		defer h.tsDataPool.Put(tsDataPtr)
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: h.computeChecks}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	
	// Use atomic round-robin to select a handle from the pool
	idx := h.handleIdx.Add(1)
	handle := h.handles[idx%uint64(len(h.handles))]
	return handle.WritePacketData(buf.Bytes())
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) setDSCP(dscp int, set bool) {
	h.dscp.Store(int32(dscp))
	h.dscpSet.Store(set)
}

func (h *SendHandle) Close() {
	for _, handle := range h.handles {
		if handle != nil {
			handle.Close()
		}
	}
}
