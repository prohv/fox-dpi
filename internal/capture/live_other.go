//go:build !windows && !linux && !darwin

package capture

import (
	"fmt"
	"runtime"
)

// OpenLive is a fallback stub for operating systems where native packet taps are not yet implemented.
func OpenLive(ifaceName string) (PacketSource, error) {
	return nil, fmt.Errorf("native live packet capture is not supported on %s; please use offline PCAP mode (-f <file.pcap>)", runtime.GOOS)
}
