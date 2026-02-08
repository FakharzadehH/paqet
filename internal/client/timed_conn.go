package client

import (
	"context"
	"paqet/internal/conf"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"sync/atomic"
	"time"
)

type timedConn struct {
	cfg            *conf.Conf
	conn           atomic.Value // stores tnet.Conn
	connValid      atomic.Bool  // tracks if conn is valid
	expire         time.Time
	ctx            context.Context
	sharedPkt      *socket.PacketConn
	recreating     atomic.Bool // Prevents concurrent recreation attempts
}

func newTimedConn(ctx context.Context, cfg *conf.Conf, sharedPkt *socket.PacketConn) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, ctx: ctx, sharedPkt: sharedPkt}
	conn, err := tc.createConn()
	if err != nil {
		return nil, err
	}
	tc.conn.Store(conn)
	tc.connValid.Store(true)

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	// Use the shared PacketConn instead of creating a new one
	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.sharedPkt)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) getConn() tnet.Conn {
	if !tc.connValid.Load() {
		return nil
	}
	if c := tc.conn.Load(); c != nil {
		return c.(tnet.Conn)
	}
	return nil
}

func (tc *timedConn) setConn(conn tnet.Conn) {
	tc.conn.Store(conn)
	tc.connValid.Store(true)
}

func (tc *timedConn) invalidateConn() {
	tc.connValid.Store(false)
}

func (tc *timedConn) close() {
	if conn := tc.getConn(); conn != nil {
		conn.Close()
	}
}
