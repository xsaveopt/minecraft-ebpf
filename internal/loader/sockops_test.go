package loader

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

var loopbackKey = [4]byte{127, 0, 0, 1}

func requireCgroup2(t *testing.T) string {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skipf("%s is not a cgroup2 mount", cgroupRoot)
	}
	return cgroupRoot
}

func loadTestSockops(t *testing.T, port uint16) *minecraftSockopsObjects {
	t.Helper()
	requireBPFPrivileges(t)
	cg := requireCgroup2(t)
	spec, err := loadMinecraftSockops()
	if err != nil {
		t.Fatalf("load sockops spec: %v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	if err := setVar(spec, "target_port", port); err != nil {
		t.Fatalf("set target_port: %v", err)
	}
	obj := &minecraftSockopsObjects{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("load sockops objects: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: obj.MinecraftSockops,
	})
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("attach sockops: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return obj
}

func loopbackListener(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, uint16(ln.Addr().(*net.TCPAddr).Port)
}

type connPair struct {
	client net.Conn
	server net.Conn
}

func connect(t *testing.T, ln net.Listener) connPair {
	t.Helper()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return connPair{client: c, server: s}
}

func (p connPair) closeFromClient(t *testing.T) {
	t.Helper()
	_ = p.client.Close()
	_ = p.server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, p.server); err != nil {
		t.Fatalf("drain server side: %v", err)
	}
	_ = p.server.Close()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openCount(t *testing.T, obj *minecraftSockopsObjects) (uint64, bool) {
	t.Helper()
	var n uint64
	err := obj.TcpOpenCount.Lookup(&loopbackKey, &n)
	if isNotExist(err) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("lookup open count: %v", err)
	}
	return n, true
}

func TestSockopsTracksOpenConnectionsAndClearsStateWhenTheLastCloses(t *testing.T) {
	ln, port := loopbackListener(t)
	obj := loadTestSockops(t, port)

	first := connect(t, ln)
	second := connect(t, ln)
	waitFor(t, "two open connections", func() bool {
		n, _ := openCount(t, obj)
		return n == 2
	})
	if !hasKey(t, obj.TcpEstablished, loopbackKey) {
		t.Fatal("an established connection did not insert tcp_established")
	}
	if got := statTotal(t, obj.Stats, statTCPEstablishedInserts); got != 2 {
		t.Errorf("tcp_established_inserts = %d, want 2", got)
	}

	now := bootNow(t)
	putTimestamp(t, obj.TcpWhitelist, loopbackKey, now)
	putTimestamp(t, obj.TcpFirstData, loopbackKey, now)

	first.closeFromClient(t)
	waitFor(t, "one open connection", func() bool {
		n, _ := openCount(t, obj)
		return n == 1
	})
	for name, m := range map[string]*ebpf.Map{
		"tcp_established": obj.TcpEstablished,
		"tcp_whitelist":   obj.TcpWhitelist,
		"tcp_first_data":  obj.TcpFirstData,
	} {
		if !hasKey(t, m, loopbackKey) {
			t.Errorf("%s was cleared while a connection from the source is still open", name)
		}
	}

	second.closeFromClient(t)
	waitFor(t, "no open connections", func() bool {
		n, _ := openCount(t, obj)
		return n == 0
	})
	for name, m := range map[string]*ebpf.Map{
		"tcp_established": obj.TcpEstablished,
		"tcp_whitelist":   obj.TcpWhitelist,
		"tcp_first_data":  obj.TcpFirstData,
	} {
		if hasKey(t, m, loopbackKey) {
			t.Errorf("%s still holds the source after its last connection closed", name)
		}
	}
}

func TestSockopsCountsAServerSideCloseToo(t *testing.T) {
	ln, port := loopbackListener(t)
	obj := loadTestSockops(t, port)

	p := connect(t, ln)
	waitFor(t, "one open connection", func() bool {
		n, _ := openCount(t, obj)
		return n == 1
	})
	_ = p.server.Close()
	_ = p.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, p.client); err != nil {
		t.Fatalf("drain client side: %v", err)
	}
	_ = p.client.Close()
	waitFor(t, "the server-initiated close to be counted", func() bool {
		n, _ := openCount(t, obj)
		return n == 0
	})
	if hasKey(t, obj.TcpEstablished, loopbackKey) {
		t.Error("tcp_established still holds the source after a server-initiated close")
	}
}

func TestSockopsIgnoresConnectionsToOtherPorts(t *testing.T) {
	ln, port := loopbackListener(t)
	obj := loadTestSockops(t, port+1)

	p := connect(t, ln)
	if _, err := p.client.Write([]byte{0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(p.server, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, ok := openCount(t, obj); ok {
		t.Error("a connection to another port was counted")
	}
	if hasKey(t, obj.TcpEstablished, loopbackKey) {
		t.Error("a connection to another port inserted tcp_established")
	}
	if got := statTotal(t, obj.Stats, statTCPEstablishedInserts); got != 0 {
		t.Errorf("tcp_established_inserts = %d, want 0", got)
	}
}
