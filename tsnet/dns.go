// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"net/netip"
	"sync"

	dnsmessage "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/dnsclient"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// DNSResolver resolves names using the tailnet's DNS configuration:
// MagicDNS, ExtraRecords, search domains, split DNS routes, and the global
// resolvers ("override local DNS" or an exit node's DNS proxy).
//
// Search-expanded names are tried in order. Short peer names resolve
// through the MagicDNS search domain. Names with no configured upstream
// or local answer fall back to the host resolver.
//
// DNSResolver follows [dnsclient.Client] resolution rules and is safe for
// concurrent use. Each lookup uses the current configuration.
type DNSResolver struct {
	s *Server
	c *dnsclient.Client

	searchMu   sync.Mutex
	searchMap  *netmap.NetworkMap // source of searchList
	searchList []dnsname.FQDN
}

// DNSResolver returns the server's cached [DNSResolver].
// Lookups start the server if needed. They wait for the backend to run,
// as in [Server.Dial].
func (s *Server) DNSResolver() *DNSResolver {
	return s.dnsRes.Get(func() *DNSResolver {
		r := &DNSResolver{s: s}
		r.c = dnsclient.New(dnsclient.Config{
			// Queries use [LocalBackend.QueryDNS] with the "tcp" family,
			// so truncated responses are retried over TCP.
			Query: func(ctx context.Context, name dnsname.FQDN, qtype dnsmessage.Type) ([]byte, bool, error) {
				bs, _, err := s.lb.QueryDNS(ctx, name.WithoutTrailingDot(), qtype)
				return bs, s.hasConfiguredDNSRoute(name), err
			},
			SearchDomains: r.searchDomains,
		})
		return r
	})
}

// hasConfiguredDNSRoute reports whether the tailnet's DNS configuration
// routes name to an upstream resolver: a split DNS route covers name, or
// global resolvers are configured. Ambient cloud-host fallback resolvers
// are excluded. If the DNS feature is not in this build, or the backend
// is not started, hasConfiguredDNSRoute returns false.
func (s *Server) hasConfiguredDNSRoute(name dnsname.FQDN) bool {
	if !buildfeatures.HasDNS {
		return false
	}
	dm, ok := s.sys.DNSManager.GetOK()
	if !ok || dm == nil {
		return false
	}
	return dm.Resolver().HasConfiguredRouteFor(name)
}

// searchDomains returns the tailnet's search domains, cached by netmap pointer.
// Netmaps are replaced, not mutated. The server must be started.
func (r *DNSResolver) searchDomains() []dnsname.FQDN {
	nm := r.s.lb.NetMap()
	r.searchMu.Lock()
	defer r.searchMu.Unlock()
	if nm == r.searchMap {
		return r.searchList
	}
	r.searchList = dnsclient.SearchDomainsFromNetmap(nm)
	r.searchMap = nm
	return r.searchList
}

// LookupHost returns host's IP addresses as strings, resolved using the
// tailnet's DNS configuration. See [DNSResolver] for resolution rules.
func (r *DNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := r.start(ctx); err != nil {
		return nil, err
	}
	return r.c.LookupHost(ctx, host)
}

// LookupIP returns host's IP addresses, resolved using the tailnet's DNS
// configuration.
// The network must be "ip", "ip4", or "ip6". The "ip" network returns both
// address families, IPv4 first. See [DNSResolver] for resolution rules.
// See [dnsclient.Client.LookupIP] for search expansion and errors.
func (r *DNSResolver) LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := r.start(ctx); err != nil {
		return nil, err
	}
	return r.c.LookupIP(ctx, network, host)
}

// LookupAddr returns addr's PTR names, resolved using the tailnet's DNS
// configuration.
// Names are fully qualified with trailing dots.
//
// Reverse lookups do not use search domains. Names without a configured
// upstream or local answer fall back to the host resolver on SERVFAIL.
func (r *DNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := r.start(ctx); err != nil {
		return nil, err
	}
	return r.c.LookupAddr(ctx, addr)
}

// start starts the server and waits for the backend to run, as in
// [Server.Dial].
func (r *DNSResolver) start(ctx context.Context) error {
	if err := r.s.Start(); err != nil {
		return err
	}
	return r.s.awaitRunning(ctx)
}

// userDialResolve resolves host for [tsdial.Dialer.UserDial] using [DNSResolver].
// It applies tailnet DNS policy to [Server.Dial].
func (s *Server) userDialResolve(ctx context.Context, network, host string, port uint16) ([]netip.AddrPort, error) {
	ips, err := s.DNSResolver().LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	return out, nil
}
