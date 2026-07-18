package loader

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Options struct {
	Iface           string
	Port            uint16
	TTL             time.Duration
	CgroupPath      string
	PinPath         string
	StatusPerMin    uint64
	StatusBurst     uint64
	LoginPerMin     uint64
	LoginBurst      uint64
	TCPGlobalPerSec uint64
	TCPGlobalBurst  uint64
	TCPMaxOpenPerIP uint64
	ConnPPS         uint64
	ConnBurst       uint64
	ConnBPS         uint64
	ConnByteBurst   uint64
	ConnNewPerSec   uint64
	ConnNewBurst    uint64
	HealthWindow    time.Duration
	HealthThreshold uint32
	HealthBlacklist time.Duration
}

type Loaded struct {
	XDPLink            link.Link
	SockopsLink        link.Link
	TCPEstablished     *ebpf.Map
	TCPSynSeen         *ebpf.Map
	TCPWhitelist       *ebpf.Map
	StatusRatelimit    *ebpf.Map
	LoginRatelimit     *ebpf.Map
	TCPGlobalRatelimit *ebpf.Map
	TCPOpenCount       *ebpf.Map
	ConnRatelimit      *ebpf.Map
	SynRatelimit       *ebpf.Map
	Health             *ebpf.Map
	IPDropHistory      *ebpf.Map
	Stats              *ebpf.Map
	XDPMode            string
}

func (l *Loaded) Close() error {
	var errs []error
	if l.SockopsLink != nil {
		if err := l.SockopsLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l.XDPLink != nil {
		if err := l.XDPLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, m := range []*ebpf.Map{
		l.TCPEstablished, l.TCPSynSeen, l.TCPWhitelist,
		l.StatusRatelimit, l.LoginRatelimit, l.TCPGlobalRatelimit,
		l.TCPOpenCount, l.ConnRatelimit, l.SynRatelimit,
		l.Health, l.IPDropHistory, l.Stats,
	} {
		if m != nil {
			_ = m.Close()
		}
	}
	return errors.Join(errs...)
}

func Load(opts Options) (*Loaded, error) {
	ifc, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", opts.Iface, err)
	}
	if err := os.MkdirAll(opts.PinPath, 0o755); err != nil {
		return nil, fmt.Errorf("create pin path: %w", err)
	}

	xobj, err := loadXDP(opts)
	if err != nil {
		return nil, err
	}
	xlink, xmode, err := attachXDP(xobj.MinecraftXdp, ifc.Index)
	if err != nil {
		closeXDPObjs(xobj)
		return nil, fmt.Errorf("attach xdp: %w", err)
	}
	_ = xobj.MinecraftXdp.Close()

	sobj, err := loadSockops(opts)
	if err != nil {
		_ = xlink.Close()
		closeXDPMaps(xobj)
		return nil, err
	}
	slink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    opts.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sobj.MinecraftSockops,
	})
	if err != nil {
		closeSockopsObjs(sobj)
		_ = xlink.Close()
		closeXDPMaps(xobj)
		return nil, fmt.Errorf("attach sockops to %s: %w", opts.CgroupPath, err)
	}
	_ = sobj.MinecraftSockops.Close()
	_ = sobj.TcpEstablished.Close()
	_ = sobj.TcpWhitelist.Close()
	_ = sobj.TcpOpenCount.Close()
	_ = sobj.Stats.Close()

	return &Loaded{
		XDPLink:            xlink,
		SockopsLink:        slink,
		TCPEstablished:     xobj.TcpEstablished,
		TCPSynSeen:         xobj.TcpSynSeen,
		TCPWhitelist:       xobj.TcpWhitelist,
		StatusRatelimit:    xobj.StatusRatelimit,
		LoginRatelimit:     xobj.LoginRatelimit,
		TCPGlobalRatelimit: xobj.TcpGlobalRatelimit,
		TCPOpenCount:       xobj.TcpOpenCount,
		ConnRatelimit:      xobj.ConnRatelimit,
		SynRatelimit:       xobj.SynRatelimit,
		Health:             xobj.Health,
		IPDropHistory:      xobj.IpDropHistory,
		Stats:              xobj.Stats,
		XDPMode:            xmode,
	}, nil
}

func loadXDP(opts Options) (*minecraftXDPObjects, error) {
	spec, err := loadMinecraftXDP()
	if err != nil {
		return nil, fmt.Errorf("load xdp spec: %w", err)
	}
	if err := setVar(spec, "target_port", opts.Port); err != nil {
		return nil, err
	}
	if err := setVar(spec, "whitelist_ttl_ns", uint64(opts.TTL.Nanoseconds())); err != nil {
		return nil, err
	}
	var statusPeriodNs uint64
	if opts.StatusPerMin > 0 {
		statusPeriodNs = (60 * 1_000_000_000) / opts.StatusPerMin
	}
	if err := setVar(spec, "status_period_ns", statusPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "status_burst", opts.StatusBurst); err != nil {
		return nil, err
	}
	var loginPeriodNs uint64
	if opts.LoginPerMin > 0 {
		loginPeriodNs = (60 * 1_000_000_000) / opts.LoginPerMin
	}
	if err := setVar(spec, "login_period_ns", loginPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "login_burst", opts.LoginBurst); err != nil {
		return nil, err
	}
	ncpu, _ := ebpf.PossibleCPU()
	if ncpu <= 0 {
		ncpu = 1
	}
	var tcpGlobalPeriodNs uint64
	if opts.TCPGlobalPerSec > 0 {
		perCPURate := opts.TCPGlobalPerSec / uint64(ncpu)
		if perCPURate == 0 {
			perCPURate = 1
		}
		tcpGlobalPeriodNs = 1_000_000_000 / perCPURate
	}
	tcpGlobalBurstPerCPU := opts.TCPGlobalBurst / uint64(ncpu)
	if opts.TCPGlobalBurst > 0 && tcpGlobalBurstPerCPU == 0 {
		tcpGlobalBurstPerCPU = 1
	}
	if err := setVar(spec, "tcp_global_period_ns", tcpGlobalPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "tcp_global_burst", tcpGlobalBurstPerCPU); err != nil {
		return nil, err
	}
	if err := setVar(spec, "tcp_max_open_per_ip", opts.TCPMaxOpenPerIP); err != nil {
		return nil, err
	}
	var connPktPeriodNs uint64
	if opts.ConnPPS > 0 {
		connPktPeriodNs = 1_000_000_000 / opts.ConnPPS
	}
	if err := setVar(spec, "conn_pkt_period_ns", connPktPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "conn_pkt_burst", opts.ConnBurst); err != nil {
		return nil, err
	}
	var connBytePeriodNs uint64
	if opts.ConnBPS > 0 {
		connBytePeriodNs = 1_000_000_000 / opts.ConnBPS
	}
	if err := setVar(spec, "conn_byte_period_ns", connBytePeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "conn_byte_burst", opts.ConnByteBurst); err != nil {
		return nil, err
	}
	var connNewPeriodNs uint64
	if opts.ConnNewPerSec > 0 {
		connNewPeriodNs = 1_000_000_000 / opts.ConnNewPerSec
	}
	if err := setVar(spec, "conn_new_period_ns", connNewPeriodNs); err != nil {
		return nil, err
	}
	if err := setVar(spec, "conn_new_burst", opts.ConnNewBurst); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_window_ns", uint64(opts.HealthWindow.Nanoseconds())); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_threshold", opts.HealthThreshold); err != nil {
		return nil, err
	}
	if err := setVar(spec, "health_blacklist_ns", uint64(opts.HealthBlacklist.Nanoseconds())); err != nil {
		return nil, err
	}
	obj := &minecraftXDPObjects{}
	if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: opts.PinPath},
	}); err != nil {
		return nil, fmt.Errorf("load xdp objects: %w", err)
	}
	return obj, nil
}

func loadSockops(opts Options) (*minecraftSockopsObjects, error) {
	spec, err := loadMinecraftSockops()
	if err != nil {
		return nil, fmt.Errorf("load sockops spec: %w", err)
	}
	if err := setVar(spec, "target_port", opts.Port); err != nil {
		return nil, err
	}
	obj := &minecraftSockopsObjects{}
	if err := spec.LoadAndAssign(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: opts.PinPath},
	}); err != nil {
		return nil, fmt.Errorf("load sockops objects: %w", err)
	}
	return obj, nil
}

func setVar(spec *ebpf.CollectionSpec, name string, value any) error {
	v, ok := spec.Variables[name]
	if !ok {
		return nil
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("set %s: %w", name, err)
	}
	return nil
}

func attachXDP(prog *ebpf.Program, ifindex int) (link.Link, string, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPDriverMode,
	})
	if err == nil {
		return l, "native", nil
	}
	l, err2 := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPGenericMode,
	})
	if err2 != nil {
		return nil, "", fmt.Errorf("native: %w; generic: %w", err, err2)
	}
	return l, "generic", nil
}

func closeXDPObjs(o *minecraftXDPObjects) {
	_ = o.MinecraftXdp.Close()
	closeXDPMaps(o)
}

func closeXDPMaps(o *minecraftXDPObjects) {
	for _, m := range []*ebpf.Map{
		o.TcpEstablished, o.TcpSynSeen, o.TcpWhitelist,
		o.StatusRatelimit, o.LoginRatelimit, o.TcpGlobalRatelimit,
		o.TcpOpenCount, o.ConnRatelimit, o.SynRatelimit,
		o.Health, o.IpDropHistory, o.Stats,
	} {
		if m != nil {
			_ = m.Close()
		}
	}
}

func closeSockopsObjs(o *minecraftSockopsObjects) {
	_ = o.MinecraftSockops.Close()
	_ = o.TcpEstablished.Close()
	_ = o.TcpWhitelist.Close()
	_ = o.TcpOpenCount.Close()
	_ = o.Stats.Close()
}
