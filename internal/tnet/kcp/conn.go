package kcp

import (
	"fmt"
	"net"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type Conn struct {
	PacketConn *socket.PacketConn
	UDPSession *kcp.UDPSession
	Session    *smux.Session
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) Ping(wait bool) error {
	// Check if session is closed first
	if c.Session.IsClosed() {
		return fmt.Errorf("session is closed")
	}
	
	// If wait=false, just checking session status is sufficient
	// Opening a stream creates unnecessary overhead on the server
	if !wait {
		return nil
	}
	
	// Full roundtrip ping for wait=true
	strm, err := c.Session.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	defer strm.Close()
	
	p := protocol.Proto{Type: protocol.PPING}
	err = p.Write(strm)
	if err != nil {
		return fmt.Errorf("strm ping write failed: %v", err)
	}
	err = p.Read(strm)
	if err != nil {
		return fmt.Errorf("strm ping read failed: %v", err)
	}
	if p.Type != protocol.PPONG {
		return fmt.Errorf("strm pong failed: unexpected type %d", p.Type)
	}
	return nil
}

func (c *Conn) Close() error {
	var err error
	if c.UDPSession != nil {
		err = c.UDPSession.Close()
	}
	if c.Session != nil {
		if e := c.Session.Close(); e != nil {
			if err == nil {
				err = e
			} else {
				err = fmt.Errorf("failed to close connections: UDPSession error: %v, Session error: %v", err, e)
			}
		}
	}
	// Do NOT close PacketConn - it's shared and managed by the Client/Listener
	return err
}

func (c *Conn) LocalAddr() net.Addr                { return c.Session.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.Session.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.Session.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.UDPSession.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.UDPSession.SetWriteDeadline(t) }
