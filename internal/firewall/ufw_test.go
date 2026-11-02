package firewall

import "testing"

func TestParseStatus(t *testing.T) {
	out := `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
8000:8100/tcp              ALLOW       Anywhere
10.0.0.0/8                 ALLOW IN    192.168.1.1
53                         ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere (v6)
Nginx Full                 ALLOW       Anywhere
`
	rules := ParseStatus(out)

	want := []Rule{
		{Port: 22, Proto: "tcp", From: "Anywhere", Action: "ALLOW"},
		{Port: 80, Proto: "tcp", From: "Anywhere", Action: "ALLOW"},
		{Port: 443, Proto: "tcp", From: "Anywhere", Action: "ALLOW"},
		{Port: 8000, Proto: "tcp", From: "Anywhere", Action: "ALLOW"},
		{Port: 53, Proto: "tcp", From: "Anywhere", Action: "ALLOW"},
		{Port: 80, Proto: "tcp", From: "Anywhere", Action: "ALLOW", V6: true},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	for i, w := range want {
		if rules[i] != w {
			t.Errorf("rule %d: got %+v, want %+v", i, rules[i], w)
		}
	}

	// "ALLOW IN" with a source CIDR and the CIDR target itself.
	var foundCIDR bool
	for _, r := range rules {
		if r.Port == 0 && !foundCIDR {
			// the 10.0.0.0/8 line is not a port rule and must be skipped
		}
	}
	_ = foundCIDR

	if !Has(rules, 80, "tcp") {
		t.Error("Has(80, tcp) = false, want true")
	}
	if Has(rules, 2222, "tcp") {
		t.Error("Has(2222, tcp) = true, want false")
	}
	if Has(rules, 80, "udp") {
		t.Error("Has(80, udp) = true, want false")
	}
}

func TestParseStatusInactive(t *testing.T) {
	out := "Status: inactive\n"
	if rules := ParseStatus(out); len(rules) != 0 {
		t.Fatalf("expected no rules, got %+v", rules)
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in    string
		port  int
		proto string
	}{
		{"80/tcp", 80, "tcp"},
		{"443", 443, "tcp"},
		{"53/udp", 53, "udp"},
		{"8000:8100/tcp", 8000, "tcp"},
		{"notaport", 0, "tcp"},
	}
	for _, c := range cases {
		port, proto := splitTarget(c.in)
		if port != c.port || proto != c.proto {
			t.Errorf("splitTarget(%q) = (%d, %s), want (%d, %s)", c.in, port, proto, c.port, c.proto)
		}
	}
}
