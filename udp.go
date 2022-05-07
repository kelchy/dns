// +build !windows

package dns

import (
	"bytes"
	"encoding/binary"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	// We can't know whether we'll get an IPv4 control message or an
	// IPv6 control message ahead of time. To get around this, we size
	// the buffer equal to the largest of the two.

	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}

	return len(oob6)
}()

// SessionUDP holds the remote address and the associated
// out-of-band data.
type SessionUDP struct {
	raddr   *net.UDPAddr
	context []byte
	proxyHdr  []byte
	proxyAddr *net.UDPAddr
}

// RemoteAddr returns the remote network address.
func (s *SessionUDP) RemoteAddr() net.Addr { return s.raddr }

// ReadFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
func ReadFromSessionUDP(conn *net.UDPConn, b []byte) (int, *SessionUDP, error) {
	oob := make([]byte, udpOOBSize)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, nil, err
	}

	// MAGIC NUMBER of cloudflare's simple proxy
	// https://developers.cloudflare.com/spectrum/proxy-protocol#enabling-proxy-protocol-v2-for-tcpudp
	MAGIC := []byte{'\x56', '\xec'}
	// if we detect the MAGIC NUMBER, we have to call simple parser to set the client details
	if n > 38 && bytes.Equal(b[:2], MAGIC[:2]) {
		// make and copy to avoid us from having issues since we will have to replace the reference b later
		proxy := make([]byte, 38)
		copy(proxy, b[:38])
		// replacing without the simple proxy header prefix as if it was a normal dns query
		copy(b, b[38:])
		// fetch the actual client's IP from proxy header
		clientIP := proxy[2:18]
		// fetch the actual client's port from proxy header
		clientPort := binary.BigEndian.Uint16(proxy[34:36])
		// create a UDPAddr
		sourceAddr := &net.UDPAddr{
			IP:   net.IP(clientIP),
			Port: int(clientPort),
		}
		// store the simple proxy header prefix in the struct for retrieval later when we reply
		return n-38, &SessionUDP{sourceAddr, oob[:oobn], proxy, raddr}, err
	}

	return n, &SessionUDP{raddr, oob[:oobn], []byte{}, nil}, err
}

// WriteToSessionUDP acts just like net.UDPConn.WriteTo(), but uses a *SessionUDP instead of a net.Addr.
func WriteToSessionUDP(conn *net.UDPConn, b []byte, session *SessionUDP) (int, error) {
	oob := correctSource(session.context)

	// if this request was made through cloudflare's simple proxy protocol, i.e. MAGIC NUMBER
	// https://developers.cloudflare.com/spectrum/proxy-protocol#enabling-proxy-protocol-v2-for-tcpudp
	if len(session.proxyHdr) > 0 {
		// prefix the original header so cloudflare can verify the source and route accordingly
		b = append(session.proxyHdr, b...)
		n, _, err := conn.WriteMsgUDP(b, oob, session.proxyAddr)
		return n, err
	}

	n, _, err := conn.WriteMsgUDP(b, oob, session.raddr)
	return n, err
}

func setUDPSocketOptions(conn *net.UDPConn) error {
	// Try setting the flags for both families and ignore the errors unless they
	// both error.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}

// parseDstFromOOB takes oob data and returns the destination IP.
func parseDstFromOOB(oob []byte) net.IP {
	// Start with IPv6 and then fallback to IPv4
	// TODO(fastest963): Figure out a way to prefer one or the other. Looking at
	// the lvl of the header for a 0 or 41 isn't cross-platform.
	cm6 := new(ipv6.ControlMessage)
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}
	cm4 := new(ipv4.ControlMessage)
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}
	return nil
}

// correctSource takes oob data and returns new oob data with the Src equal to the Dst
func correctSource(oob []byte) []byte {
	dst := parseDstFromOOB(oob)
	if dst == nil {
		return nil
	}
	// If the dst is definitely an IPv6, then use ipv6's ControlMessage to
	// respond otherwise use ipv4's because ipv6's marshal ignores ipv4
	// addresses.
	if dst.To4() == nil {
		cm := new(ipv6.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	} else {
		cm := new(ipv4.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	}
	return oob
}
