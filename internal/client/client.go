package client

import (
	"context"
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/iterator"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"sync"
)

type Client struct {
	cfg        *conf.Conf
	iter       *iterator.Iterator[*timedConn]
	udpPool    *udpPool
	mu         sync.Mutex
	sharedPkt  *socket.PacketConn // Shared PacketConn for all KCP connections
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		iter:    &iterator.Iterator[*timedConn]{},
		udpPool: &udpPool{strms: make(map[uint64]tnet.Strm)},
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	// Create a single shared PacketConn for all KCP connections
	netCfg := c.cfg.Network
	sharedPkt, err := socket.New(ctx, &netCfg)
	if err != nil {
		return fmt.Errorf("could not create shared packet conn: %w", err)
	}
	c.sharedPkt = sharedPkt

	for i := range c.cfg.Transport.Conn {
		tc, err := newTimedConn(ctx, c.cfg, sharedPkt)
		if err != nil {
			flog.Errorf("failed to create connection %d: %v", i+1, err)
			return err
		}
		flog.Debugf("client connection %d created successfully", i+1)
		c.iter.Items = append(c.iter.Items, tc)
	}
	go c.ticker(ctx)

	go func() {
		<-ctx.Done()
		for _, tc := range c.iter.Items {
			tc.close()
		}
		if c.sharedPkt != nil {
			c.sharedPkt.Close()
		}
		flog.Infof("client shutdown complete")
	}()

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %s (%d connections)", ipv4Addr, ipv6Addr, c.cfg.Server.Addr, len(c.iter.Items))
	return nil
}
