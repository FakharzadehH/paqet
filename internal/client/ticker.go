package client

import (
	"context"
	"paqet/internal/flog"
	"paqet/internal/tnet"
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
						// Try to recreate if nil
						if tc.recreating.CompareAndSwap(false, true) {
							defer tc.recreating.Store(false)
							// Check context before trying to recreate
							select {
							case <-ctx.Done():
								return
							default:
							}
							if newConn, err := tc.createConn(); err == nil {
								tc.setConn(newConn)
							} else {
								flog.Debugf("failed to recreate nil connection: %v", err)
							}
						}
						return
					}
					if err := conn.Ping(false); err != nil {
						// Connection is unhealthy, attempt to recreate with retries
						if tc.recreating.CompareAndSwap(false, true) {
							defer tc.recreating.Store(false)
							conn.Close()
							// Retry with backoff
							var newConn tnet.Conn
							var createErr error
							for attempt := 0; attempt < 3; attempt++ {
								// Check context before each retry
								select {
								case <-ctx.Done():
									tc.invalidateConn()
									return
								default:
								}
								newConn, createErr = tc.createConn()
								if createErr == nil {
									break
								}
								time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
							}
							if createErr != nil {
								// Invalidate connection
								tc.invalidateConn()
								flog.Errorf("failed to recreate connection after retries: %v", createErr)
							} else {
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
