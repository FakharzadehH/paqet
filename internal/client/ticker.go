package client

import (
	"context"
	"time"
)

func (c *Client) ticker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Perform async health checks on all connections
			for _, tc := range c.iter.Items {
				go func(tc *timedConn) {
					conn := tc.getConn()
					if conn == nil {
						return
					}
					if err := conn.Ping(false); err != nil {
						// Connection is unhealthy, attempt to recreate
						// Use atomic CAS to ensure only one goroutine recreates
						if tc.recreating.CompareAndSwap(false, true) {
							defer tc.recreating.Store(false)
							
							conn.Close()
							if newConn, err := tc.createConn(); err == nil {
								tc.setConn(newConn)
							}
						}
					}
				}(tc)
			}
		case <-ctx.Done():
			return
		}
	}
}
