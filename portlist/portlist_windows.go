// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/net/netstat"
	"tailscale.com/util/winutil"
)

const pollInterval = 5 * time.Second

func init() {
	newOSImpl = newWindowsImpl
}

type famPort struct {
	proto string
	port  uint16
	pid   uint32
}

type windowsImpl struct {
	known map[famPort]*portMeta // inode string => metadata
}

type portMeta struct {
	port Port
	keep bool
}

func newWindowsImpl() osImpl {
	return &windowsImpl{
		known: map[famPort]*portMeta{},
	}
}

func (*windowsImpl) Close() error { return nil }

func (im *windowsImpl) AppendListeningPorts(base []Port) ([]Port, error) {
	// TODO(bradfitz): netstat.Get makes a bunch of garbage. Add an Append-style
	// API to that package instead/additionally.
	tab, err := netstat.Get()
	if err != nil {
		return nil, err
	}

	pi := newPidInfo()

	for _, pm := range im.known {
		pm.keep = false
	}

	ret := base
	for _, e := range tab.Entries {
		if e.State != "LISTEN" {
			continue
		}
		if !e.Local.Addr().IsUnspecified() {
			continue
		}
		fp := famPort{
			proto: "tcp", // TODO(bradfitz): UDP too; add to netstat
			port:  e.Local.Port(),
			pid:   uint32(e.Pid),
		}
		pm, ok := im.known[fp]
		if ok {
			pm.keep = true
			continue
		}
		pm = &portMeta{
			keep: true,
			port: Port{
				Proto:   "tcp",
				Port:    e.Local.Port(),
				Process: pi.get(uint32(e.Pid)),
			},
		}
		im.known[fp] = pm
	}

	for k, m := range im.known {
		if !m.keep {
			delete(im.known, k)
			continue
		}
		ret = append(ret, m.port)
	}

	return sortAndDedup(ret), nil
}

// pidInfo is a mapping of process IDs to process names that incorporates
// information from Windows' Service Control Manager. We use this information
// to disambiguate svchost processes (when possible).
type pidInfo map[uint32]string

// newPidInfo instantiates a pidInfo and pre-populates it with PID mappings for
// all Windows services that are currently running.
func newPidInfo() (result pidInfo) {
	defer func() {
		// Default to empty if we failed to obtain the service list.
		if result == nil {
			result = make(pidInfo)
		}
	}()

	scm, err := winutil.ConnectToLocalSCMForRead()
	if err != nil {
		return result
	}
	defer scm.Disconnect()

	services, err := scm.ListServices()
	if err != nil {
		return result
	}

	result = make(pidInfo, len(services))

	// Pre-populate result with the PIDs for all running services.
	for _, s := range services {
		result.maybeAddService(scm, s)
	}

	return result
}

// maybeAddService attempts to obtain PID information about the service named
// svcName, and adds either its process name, or in the case of services hosted
// by svchost.exe, svcName itself, to pi.
func (pi pidInfo) maybeAddService(scm *mgr.Mgr, svcName string) {
	service, err := winutil.OpenServiceForRead(scm, svcName)
	if err != nil {
		return
	}
	defer service.Close()

	status, err := service.Query()
	// Stopped services do not have PIDs, and StopPending services will
	// imminently become defunct.
	if err != nil || status.State == svc.Stopped || status.State == svc.StopPending || status.ProcessId == 0 {
		return
	}

	if _, ok := pi[status.ProcessId]; ok {
		// We already have seen this process (possible with shared services).
		return
	}

	procName, err := getProcessName(status.ProcessId)
	if err != nil {
		return
	}

	useName := &procName
	if strings.EqualFold(procName, "svchost") {
		if cfg, err := service.Config(); err == nil && cfg.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS {
			// For services hosted individually inside a svchost process, substitute
			// the name of the service for the name of the process.
			useName = &svcName
		}

		// Otherwise there are multiple services hosted by this process and we do
		// not have a way to automagically know which service is the "correct" one
		// that corresponds to a particular port.
	}

	pi[status.ProcessId] = *useName
}

func (pi pidInfo) get(pid uint32) string {
	if s, ok := pi[pid]; ok {
		return s
	}

	procName, err := getProcessName(pid)
	if err != nil {
		return ""
	}

	pi[pid] = procName
	return procName
}

// getProcessName returns the name of the executable image corresponding to the
// process identified by pid, with path and extension stripped off.
func getProcessName(pid uint32) (string, error) {
	procName, err := winutil.GetProcessImageName(pid)
	if err != nil {
		return "", nil
	}

	return strings.TrimSuffix(filepath.Base(procName), filepath.Ext(procName)), nil
}

func appendListeningPorts([]Port) ([]Port, error) {
	panic("unused on windows; needed to compile for now")
}

func addProcesses([]Port) ([]Port, error) {
	panic("unused on windows; needed to compile for now")
}
