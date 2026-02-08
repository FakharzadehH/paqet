package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{handle: handle}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	// Manual minimal packet parsing
	// We need: source IP, source port, and payload
	
	// Minimum packet size check (Ethernet header = 14 bytes)
	if len(data) < 14 {
		return nil, nil, nil
	}

	addr := &net.UDPAddr{}
	
	// Parse Ethernet header (14 bytes)
	// EtherType is at bytes 12-13
	etherType := uint16(data[12])<<8 | uint16(data[13])
	
	var ipHeaderStart int
	var ipVersion byte
	var protocol byte
	var srcIP net.IP
	var ipHeaderLen int
	
	switch etherType {
	case 0x0800: // IPv4
		ipHeaderStart = 14
		if len(data) < ipHeaderStart+20 {
			return nil, nil, nil
		}
		
		ipVersion = data[ipHeaderStart] >> 4
		if ipVersion != 4 {
			return nil, nil, nil
		}
		
		// IP header length is in the lower 4 bits of the first byte (in 32-bit words)
		ipHeaderLen = int(data[ipHeaderStart]&0x0F) * 4
		if ipHeaderLen < 20 {
			return nil, nil, nil
		}
		
		// Protocol is at byte 9 of IP header
		protocol = data[ipHeaderStart+9]
		
		// Source IP is at bytes 12-15 of IP header
		srcIP = net.IPv4(data[ipHeaderStart+12], data[ipHeaderStart+13], 
			data[ipHeaderStart+14], data[ipHeaderStart+15])
	
	case 0x86DD: // IPv6
		ipHeaderStart = 14
		if len(data) < ipHeaderStart+40 {
			return nil, nil, nil
		}
		
		ipVersion = data[ipHeaderStart] >> 4
		if ipVersion != 6 {
			return nil, nil, nil
		}
		
		ipHeaderLen = 40 // IPv6 header is fixed 40 bytes
		
		// Next Header (protocol) is at byte 6 of IPv6 header
		protocol = data[ipHeaderStart+6]
		
		// Source IP is at bytes 8-23 of IPv6 header
		srcIP = make(net.IP, 16)
		copy(srcIP, data[ipHeaderStart+8:ipHeaderStart+24])
	
	default:
		// Unknown EtherType
		return nil, nil, nil
	}
	
	addr.IP = srcIP
	
	// Parse TCP header
	tcpHeaderStart := ipHeaderStart + ipHeaderLen
	if protocol != 6 { // TCP protocol number
		return nil, nil, nil
	}
	
	if len(data) < tcpHeaderStart+20 {
		return nil, nil, nil
	}
	
	// Source port is at bytes 0-1 of TCP header
	addr.Port = int(uint16(data[tcpHeaderStart])<<8 | uint16(data[tcpHeaderStart+1]))
	
	// TCP header length is in the upper 4 bits of byte 12 (data offset, in 32-bit words)
	tcpHeaderLen := int(data[tcpHeaderStart+12]>>4) * 4
	if tcpHeaderLen < 20 {
		return nil, nil, nil
	}
	
	// Payload starts after TCP header
	payloadStart := tcpHeaderStart + tcpHeaderLen
	if payloadStart >= len(data) {
		// No payload
		return nil, nil, nil
	}
	
	payload := data[payloadStart:]
	if len(payload) == 0 {
		return nil, nil, nil
	}
	
	return payload, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
