// SPDX-License-Identifier: AGPL-3.0-or-later

package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBlocked(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fd00:ec2::254", "fc00::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2002:a9fe:a9fe::1",
	}
	for _, s := range blocked {
		if !Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "64:ff9b::808:808", "2002:808:808::1"}
	for _, s := range allowed {
		if Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	if !Blocked(netip.Addr{}) {
		t.Error("invalid address not blocked")
	}
}

func TestCheckHost(t *testing.T) {
	old := LookupNetIP
	defer func() { LookupNetIP = old }()
	LookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example.com":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		case "mixed.example.com":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")}, nil
		case "meta.example.com":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		return nil, errors.New("no such host")
	}
	ctx := context.Background()
	for _, h := range []string{"public.example.com", "8.8.8.8", "[2606:4700:4700::1111]", ""} {
		if err := CheckHost(ctx, h); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
	for _, h := range []string{"mixed.example.com", "meta.example.com", "127.0.0.1", "localhost", "minio", "db.svc", "x.internal",
		"printer.local", "unknown.example.com", "fe80::1%eth0", "[::1]", "10.0.0.1"} {
		if err := CheckHost(ctx, h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	if err := CheckHost(ctx, "127.0.0.1"); !errors.Is(err, ErrBlocked) {
		t.Errorf("want ErrBlocked, got %v", err)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"smtp.example.com":                    "smtp.example.com",
		"smtp.example.com:587":                "smtp.example.com",
		"https://u:p@hook.example.com:8443/x": "hook.example.com",
		"http://[::1]:9000":                   "::1",
		"[fd00::1]:514":                       "fd00::1",
		"https://login.example.com/realms/a":  "login.example.com",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// The dial-time check sees the resolved address, so a name that points at
// loopback (DNS rebinding) is refused even though no name check ran.
func TestDialerRefusesLoopbackAtConnectTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, target := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		c, err := Dialer(2*time.Second).DialContext(context.Background(), "tcp", target)
		if err == nil {
			c.Close()
			t.Fatalf("%s: connected", target)
		}
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("%s: want ErrBlocked, got %v", target, err)
		}
	}
	// Without the guard the same target is reachable (the test is meaningful).
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
