package protocol

import "testing"

type mockDissector struct{}

func (m *mockDissector) Name() string { return "MOCK" }

func (m *mockDissector) Inspect(payload []byte) (Verdict, Metadata, error) {
	if len(payload) == 0 {
		return VerdictUnknown, Metadata{}, nil
	}
	if len(payload) < 4 {
		return VerdictNeedMoreData, Metadata{}, nil
	}
	if string(payload[:4]) == "TEST" {
		return VerdictMatched, Metadata{
			Protocol: "MOCK",
			Host:     "mock.local",
			Details:  map[string]string{"type": "mock"},
		}, nil
	}
	return VerdictUnknown, Metadata{}, nil
}

func Test_DissectorContract(t *testing.T) {
	var d Dissector = &mockDissector{}

	if d.Name() != "MOCK" {
		t.Fatalf("expected name MOCK, got %s", d.Name())
	}

	v1, _, _ := d.Inspect(nil)
	if v1 != VerdictUnknown {
		t.Fatalf("expected VerdictUnknown for empty payload, got %v", v1)
	}

	v2, _, _ := d.Inspect([]byte("TE"))
	if v2 != VerdictNeedMoreData {
		t.Fatalf("expected VerdictNeedMoreData, got %v", v2)
	}

	v3, meta, err := d.Inspect([]byte("TEST_PAYLOAD"))
	if err != nil || v3 != VerdictMatched || meta.Host != "mock.local" {
		t.Fatalf("expected VerdictMatched with host mock.local, got %v, meta=%+v, err=%v", v3, meta, err)
	}
}
