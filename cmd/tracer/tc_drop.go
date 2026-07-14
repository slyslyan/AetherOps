package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// initTCDrop 加载 eBPF TC 程序并挂载到网络接口的 TCX ingress 方向。
func (a *App) initTCDrop() error {
	var objs tc_dropObjects
	if err := loadTc_dropObjects(&objs, nil); err != nil {
		return err
	}

	iface, err := net.InterfaceByName(a.ifaceName)
	if err != nil {
		objs.Close()
		return err
	}

	tcx, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcDropIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return err
	}

	a.tcDropObjs = objs
	a.tcDropProg = objs.TcDropIngress
	a.tcDropLink = tcx

	slog.Info(fmt.Sprintf("eBPF TC 程序已挂载到 %s (index %d, ingress)", a.ifaceName, iface.Index))
	return nil
}

// closeTCDrop 分离 eBPF TC 程序并释放资源。
func (a *App) closeTCDrop() {
	if a.tcDropLink != nil {
		a.tcDropLink.Close()
		a.tcDropLink = nil
	}
	a.tcDropObjs.Close()
	a.tcDropProg = nil
}
