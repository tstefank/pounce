//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Peer is the verified identity of a connected socket peer.
type Peer struct {
	UID uint32
	PID int
}

// PeerCred returns the credentials of the process on the other end of conn,
// using LOCAL_PEERCRED (uid) and LOCAL_PEERPID (pid). The daemon uses this to
// vet and label unprivileged callers before trusting their registration.
func PeerCred(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var sockErr error
	cerr := raw.Control(func(fd uintptr) {
		xu, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			sockErr = fmt.Errorf("LOCAL_PEERCRED: %w", e)
			return
		}
		peer.UID = xu.Uid
		if pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); e == nil {
			peer.PID = pid
		}
	})
	if cerr != nil {
		return Peer{}, cerr
	}
	if sockErr != nil {
		return Peer{}, sockErr
	}
	return peer, nil
}
