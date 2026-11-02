package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	SetDir(tmp)
	defer SetDir("")

	st := Default()
	st.Initialised = true
	st.NginxMode = ModeHost
	st.Sites["api.example.com"] = &Site{
		Domain:  "api.example.com",
		Kind:    KindProxy,
		Target:  "127.0.0.1:3000",
		SSL:     true,
		Enabled: true,
	}
	st.TrackPort(80, "tcp", "", true)
	st.TrackPort(443, "tcp", "", true)

	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "state.json")); err != nil {
		t.Fatalf("state.json not written: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	site := loaded.Sites["api.example.com"]
	if site == nil {
		t.Fatal("site missing after round trip")
	}
	if !site.SSL || site.Target != "127.0.0.1:3000" {
		t.Errorf("site = %+v", site)
	}
	if !loaded.OwnedPort(80, "tcp").Owned {
		t.Error("port 80 should be owned")
	}
	if loaded.NginxMode != ModeHost {
		t.Errorf("mode = %q", loaded.NginxMode)
	}
}

func TestLoadMissingReturnsDefault(t *testing.T) {
	SetDir(t.TempDir())
	defer SetDir("")

	st, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Sites == nil || st.Ports == nil {
		t.Error("default state must have initialized maps")
	}
	if st.Webroot != DefaultWebroot {
		t.Errorf("webroot = %q", st.Webroot)
	}
}

func TestTrackPortIdempotentOwnership(t *testing.T) {
	st := Default()
	st.TrackPort(80, "tcp", "", false) // pre-existing rule
	st.TrackPort(80, "tcp", "", true)  // later marked owned
	if !st.OwnedPort(80, "tcp").Owned {
		t.Error("ownership must not be lost when re-tracking")
	}
	// owned must not downgradest.TrackPort(80, "tcp", "", false)
	if !st.OwnedPort(80, "tcp").Owned {
		t.Error("ownership must not downgrade to false")
	}
	st.UntrackPort(80, "tcp")
	if st.OwnedPort(80, "tcp") != nil {
		t.Error("port should be untracked")
	}
}

func TestPortKey(t *testing.T) {
	if got := PortKey(80, "tcp"); got != "80/tcp" {
		t.Errorf("PortKey = %q", got)
	}
}
