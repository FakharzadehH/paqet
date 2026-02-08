package socket

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"paqet/internal/conf"
	"sync/atomic"
	"time"
)

type packetData struct {
	payload []byte
	addr    net.Addr
	err     error
}

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value
	dscp          atomic.Int32
	dscpSet       atomic.Bool // Track if DSCP was explicitly set
	packets       chan packetData

	ctx    context.Context
	cancel context.CancelFunc
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		packets:    make(chan packetData, 1024), // Buffered channel for async reads
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start background reader goroutine
	go conn.readLoop()

	return conn, nil
}

// readLoop continuously reads packets from pcap and sends them to the packets channel
func (c *PacketConn) readLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		payload, addr, err := c.recvHandle.Read()
		pkt := packetData{
			payload: payload,
			addr:    addr,
			err:     err,
		}

		select {
		case c.packets <- pkt:
		case <-c.ctx.Done():
			return
		}

		if err != nil {
			// On error (e.g., temporary read failures, no packets available),
			// slow down to avoid busy loop and excessive CPU usage
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		delay := time.Until(d)
		if delay <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(delay)
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-c.packets:
		if pkt.err != nil {
			return 0, nil, pkt.err
		}
		n = copy(data, pkt.payload)
		return n, pkt.addr, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	err = c.sendHandle.Write(data, daddr)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.cancel()

	if c.sendHandle != nil {
		go c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		go c.recvHandle.Close()
	}

	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
	// return &net.UDPAddr{
	// 	IP:   append([]byte(nil), c.cfg.PrimaryAddr().IP...),
	// 	Port: c.cfg.PrimaryAddr().Port,
	// 	Zone: c.cfg.PrimaryAddr().Zone,
	// }
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	c.dscp.Store(int32(dscp))
	c.dscpSet.Store(true)
	c.sendHandle.setDSCP(dscp, true)
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}
