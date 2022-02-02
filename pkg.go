// Package restricted provides functions to dial a restricted subset of IP addresses.
package restricted

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// Dialer encapsulates DNS resolution, IP blocking, and dialing logic; it only
// supports TCP network.
//
// Example:
//
// 	d := &restricted.Dialer{Block:func(ip netip.Addr) bool {return ip.IsPrivate()}}
// 	// connection will be refused if somehost.net resolves to private subnet range
// 	conn, err := d.DialContext(ctx, "tcp", "somehost.net:1234")
type Dialer struct {
	// Optional resolver to use
	Resolver net.Resolver
	// Optional dialer to use, it's only called with an already resolved
	// address (host:port)
	Dialer net.Dialer
	// Optional function that decides whether connection to a specific IP
	// address should be denied. Dialer always denies access to unspecified and
	// loopback addresses, this function can extend this logic. Address is
	// blocked if it returns true.
	Block func(netip.Addr) bool
}

// DialContext works similar to net.Dialer.DialContext, but it first resolves
// both address and port, and verifies that address is not blocked. Dialer
// always denies access to unspecified and loopback addresses. Set Dialer.Block
// to customize additional block logic.
//
// DialContext only supports TCP network.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	const tcpNetwork = "tcp"
	if network != tcpNetwork {
		return nil, errors.New("restricted.Dialer only supports tcp")
	}
	var (
		err        error
		host, port string
		portnum    int
	)
	if host, port, err = net.SplitHostPort(addr); err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("empty host")
	}
	if portnum, err = d.Resolver.LookupPort(ctx, network, port); err != nil {
		return nil, err
	}
	ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		ip = ip.Unmap()
		if d.Block != nil && d.Block(ip) {
			continue
		}
		// TODO: split timeout evenly among attempts, similar to how net.Dialer.DialContext does it
		conn, err := d.Dialer.DialContext(ctx, tcpNetwork, net.JoinHostPort(ip.String(), strconv.Itoa(portnum)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() == nil {
			continue
		}
		return nil, err
	}
	if lastErr == nil {
		return nil, errors.New("cannot resolve address to any non-blocked IP")
	}
	return nil, fmt.Errorf("failed to dial any non-blocked addresses, last error was: %w", lastErr)
}
