package ops

import "testing"

func TestNormalizeProxy(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"3000", "127.0.0.1:3000", true},
		{"localhost:3000", "localhost:3000", true},
		{"http://127.0.0.1:3000/", "127.0.0.1:3000", true},
		{"https://example.com:8443", "example.com:8443", true},
		{" 3000 ", "127.0.0.1:3000", true},
		{"", "", false},
		{"notaport", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeProxy(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("NormalizeProxy(%q) error: %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("NormalizeProxy(%q) = %q, want %q", c.in, got, c.want)
			}
		} else if err == nil {
			t.Errorf("NormalizeProxy(%q) = %q, want error", c.in, got)
		}
	}
}

func TestAddSiteValidatesTargets(t *testing.T) {
	o := New()
	// zero targets
	if _, err := o.AddSite(SiteAddInput{Domain: "a.com"}); err == nil {
		t.Error("expected error for no target")
	}
	// two targets
	if _, err := o.AddSite(SiteAddInput{Domain: "a.com", Proxy: "3000", Root: "/tmp"}); err == nil {
		t.Error("expected error for two targets")
	}
	// missing domain
	if _, err := o.AddSite(SiteAddInput{Proxy: "3000"}); err == nil {
		t.Error("expected error for missing domain")
	}
	// relative root
	if _, err := o.AddSite(SiteAddInput{Domain: "a.com", Root: "relative/path"}); err == nil {
		t.Error("expected error for relative root")
	}
}

func TestNormalizeProto(t *testing.T) {
	if got := normalizeProto(""); got != "tcp" {
		t.Errorf("normalizeProto(\"\") = %q, want tcp", got)
	}
	if got := normalizeProto("UDP"); got != "udp" {
		t.Errorf("normalizeProto(UDP) = %q, want udp", got)
	}
	if got := normalizeProto("tcp"); got != "tcp" {
		t.Errorf("normalizeProto(tcp) = %q", got)
	}
}

func TestHostIPOrAll(t *testing.T) {
	if got := hostIPOrAll(""); got != "0.0.0.0" {
		t.Errorf("hostIPOrAll(\"\") = %q", got)
	}
	if got := hostIPOrAll("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("hostIPOrAll = %q", got)
	}
}

func TestAmbiguousErrorListsCandidates(t *testing.T) {
	e := &AmbiguousError{
		Container: "myapp",
		Candidates: []ContainerPort{
			{HostPort: 3000}, {HostPort: 8080},
		},
	}
	msg := e.Error()
	if !contains(msg, "myapp") || !contains(msg, "127.0.0.1:3000") || !contains(msg, "127.0.0.1:8080") {
		t.Errorf("AmbiguousError message missing candidates: %s", msg)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
