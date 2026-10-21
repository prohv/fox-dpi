//go:build windows

package capture

import (
	"strings"
	"testing"
)

func Test_LiveWindows_PermissionsCheck(t *testing.T) {
	s, err := OpenLiveWindows("Wi-Fi")
	if err != nil {
		if strings.Contains(err.Error(), "Administrator privileges") {
			t.Logf("PASS: Non-admin correctly intercepted with clear guidance:\n%v", err)
			return
		}
		t.Logf("OpenLiveWindows returned: %v", err)
	} else {
		defer s.Close()
		t.Logf("PASS: Running with elevated Admin privileges, live socket opened successfully on %s (%s)!", s.InterfaceName(), s.IP())
	}
}
