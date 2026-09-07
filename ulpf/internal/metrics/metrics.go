package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Collector collects internal metrics
type Collector struct {
	eventsReceived uint64
	eventsDurable  uint64
	eventsParsed   uint64
	eventsNormalized uint64
	eventsFailed   uint64
	eventsQuarantined uint64
	bytesReceived  uint64
	bytesWritten   uint64
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{}
}

// IncrementEventsReceived increments the events received counter
func (c *Collector) IncrementEventsReceived() {
	atomic.AddUint64(&c.eventsReceived, 1)
}

// IncrementEventsDurable increments the events durable counter
func (c *Collector) IncrementEventsDurable() {
	atomic.AddUint64(&c.eventsDurable, 1)
}

// IncrementEventsParsed increments the events parsed counter
func (c *Collector) IncrementEventsParsed() {
	atomic.AddUint64(&c.eventsParsed, 1)
}

// IncrementEventsNormalized increments the events normalized counter
func (c *Collector) IncrementEventsNormalized() {
	atomic.AddUint64(&c.eventsNormalized, 1)
}

// IncrementEventsFailed increments the events failed counter
func (c *Collector) IncrementEventsFailed() {
	atomic.AddUint64(&c.eventsFailed, 1)
}

// IncrementEventsQuarantined increments the events quarantined counter
func (c *Collector) IncrementEventsQuarantined() {
	atomic.AddUint64(&c.eventsQuarantined, 1)
}

// AddBytesReceived adds to the bytes received counter
func (c *Collector) AddBytesReceived(n int64) {
	atomic.AddUint64(&c.bytesReceived, uint64(n))
}

// AddBytesWritten adds to the bytes written counter
func (c *Collector) AddBytesWritten(n int64) {
	atomic.AddUint64(&c.bytesWritten, uint64(n))
}

// Handler returns an HTTP handler for /metrics endpoint
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP events_received_total Total events received\n")
		fmt.Fprintf(w, "# TYPE events_received_total counter\n")
		fmt.Fprintf(w, "events_received_total %d\n", atomic.LoadUint64(&c.eventsReceived))
		fmt.Fprintf(w, "# HELP events_durable_total Total events durably stored\n")
		fmt.Fprintf(w, "# TYPE events_durable_total counter\n")
		fmt.Fprintf(w, "events_durable_total %d\n", atomic.LoadUint64(&c.eventsDurable))
		fmt.Fprintf(w, "# HELP events_parsed_total Total events parsed\n")
		fmt.Fprintf(w, "# TYPE events_parsed_total counter\n")
		fmt.Fprintf(w, "events_parsed_total %d\n", atomic.LoadUint64(&c.eventsParsed))
		fmt.Fprintf(w, "# HELP events_normalized_total Total events normalized to OCSF\n")
		fmt.Fprintf(w, "# TYPE events_normalized_total counter\n")
		fmt.Fprintf(w, "events_normalized_total %d\n", atomic.LoadUint64(&c.eventsNormalized))
		fmt.Fprintf(w, "# HELP events_failed_total Total events that failed processing\n")
		fmt.Fprintf(w, "# TYPE events_failed_total counter\n")
		fmt.Fprintf(w, "events_failed_total %d\n", atomic.LoadUint64(&c.eventsFailed))
		fmt.Fprintf(w, "# HELP events_quarantined_total Total events sent to quarantine\n")
		fmt.Fprintf(w, "# TYPE events_quarantined_total counter\n")
		fmt.Fprintf(w, "events_quarantined_total %d\n", atomic.LoadUint64(&c.eventsQuarantined))
		fmt.Fprintf(w, "# HELP bytes_received_total Total bytes received\n")
		fmt.Fprintf(w, "# TYPE bytes_received_total counter\n")
		fmt.Fprintf(w, "bytes_received_total %d\n", atomic.LoadUint64(&c.bytesReceived))
		fmt.Fprintf(w, "# HELP bytes_written_total Total bytes written\n")
		fmt.Fprintf(w, "# TYPE bytes_written_total counter\n")
		fmt.Fprintf(w, "bytes_written_total %d\n", atomic.LoadUint64(&c.bytesWritten))
	})
}