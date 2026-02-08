package metrics

import (
	"paqet/internal/flog"
	"sync/atomic"
	"time"
)

var (
	ActiveStreams  atomic.Int64
	TotalStreams   atomic.Int64
	ActiveConns    atomic.Int64
	BytesSent      atomic.Int64
	BytesReceived  atomic.Int64
	PacketsDropped atomic.Int64
	StreamErrors   atomic.Int64
)

func StartReporter(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			flog.Infof("[metrics] streams: %d active / %d total | conns: %d | bytes: %d sent / %d recv | drops: %d | errors: %d",
				ActiveStreams.Load(),
				TotalStreams.Load(),
				ActiveConns.Load(),
				BytesSent.Load(),
				BytesReceived.Load(),
				PacketsDropped.Load(),
				StreamErrors.Load(),
			)
		}
	}()
}
