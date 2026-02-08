package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"
)

func (c *Client) newConn() (tnet.Conn, error) {
	// Use lock-free round-robin connection selection
	tc := c.iter.Next()
	return tc.getConn(), nil
}

func (c *Client) newStrm() (tnet.Strm, error) {
	const maxRetries = 5 // Safe max: backoff won't overflow with reasonable values
	backoff := 50 * time.Millisecond
	const maxBackoff = 500 * time.Millisecond

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
			if backoff > maxBackoff {
				backoff = maxBackoff // Cap backoff at 500ms
			}
			flog.Debugf("retry attempt %d/%d", retry+1, maxRetries)
		}

		conn, err := c.newConn()
		if err != nil {
			flog.Debugf("session creation failed: %v", err)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			flog.Debugf("failed to open stream: %v", err)
			continue
		}
		return strm, nil
	}
	return nil, fmt.Errorf("failed to create stream after %d retries", maxRetries)
}
