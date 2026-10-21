package sink

import (
	"fmt"
	"os"
)

// ConsoleAlertSink wraps an underlying Sink and prints real-time alerts to stderr.
type ConsoleAlertSink struct {
	underlying Sink
	live       bool
}

// NewConsoleAlertSink initializes the wrapper. If live is true, alerts are echoed to stderr.
func NewConsoleAlertSink(underlying Sink, live bool) *ConsoleAlertSink {
	return &ConsoleAlertSink{
		underlying: underlying,
		live:       live,
	}
}

func (s *ConsoleAlertSink) EmitFlow(event FlowEvent) {
	s.underlying.EmitFlow(event)
}

func (s *ConsoleAlertSink) EmitAlert(event AlertEvent) {
	s.underlying.EmitAlert(event)
	if s.live {
		fmt.Fprintf(os.Stderr, "\n[ALERT] [%s] %s: %s\n        Endpoints: %s:%d -> %s:%d (%s)\n",
			event.Severity, event.Rule, event.Message,
			event.SrcIP, event.SrcPort, event.DstIP, event.DstPort, event.Protocol)
	}
}

func (s *ConsoleAlertSink) Stats() Stats {
	return s.underlying.Stats()
}

func (s *ConsoleAlertSink) Close() error {
	return s.underlying.Close()
}
