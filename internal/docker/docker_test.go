package docker

import "testing"

func TestParseInspect(t *testing.T) {
	out := `[
  {
    "Name": "/myapp",
    "State": {"Running": true},
    "HostConfig": {
      "PortBindings": {
        "3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}],
        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
      }
    }
  },
  {
    "Name": "/db",
    "State": {"Running": false},
    "HostConfig": {"PortBindings": null}
  }
]`
	list, err := parseInspect(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d containers", len(list))
	}
	app := list[0]
	if app.Name != "myapp" || !app.Running {
		t.Errorf("app = %+v", app)
	}
	if len(app.Bindings) != 2 {
		t.Fatalf("bindings = %+v", app.Bindings)
	}
	// sorted by container port: 3000 before 8080
	if app.Bindings[0].HostPort != 3000 || app.Bindings[0].HostIP != "127.0.0.1" {
		t.Errorf("binding[0] = %+v", app.Bindings[0])
	}
	if !app.Bindings[1].Exposed() {
		t.Error("0.0.0.0 binding must be Exposed()")
	}
	if app.Bindings[0].Exposed() {
		t.Error("127.0.0.1 binding must not be Exposed()")
	}
	if db := list[1]; db.Name != "db" || db.Running || len(db.Bindings) != 0 {
		t.Errorf("db = %+v", db)
	}
}

func TestParseInspectRandomPort(t *testing.T) {
	// docker reports the actually-assigned host port even with -p 3000
	out := `[{"Name":"/app","State":{"Running":true},
	  "HostConfig":{"PortBindings":{"3000/tcp":[{"HostIp":"","HostPort":"49155"}]}}}]`
	list, err := parseInspect(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(list[0].Bindings) != 1 || list[0].Bindings[0].HostPort != 49155 {
		t.Errorf("bindings = %+v", list[0].Bindings)
	}
	// empty HostIP means all interfaces
	if !list[0].Bindings[0].Exposed() {
		t.Error("empty HostIP must count as exposed")
	}
}
