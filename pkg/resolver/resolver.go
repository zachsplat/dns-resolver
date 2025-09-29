package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/zachsplat/dns-resolver/pkg/dns"
)

var rootServers = []string{
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
}

type Resolver struct {
	Trace   bool
	timeout time.Duration
}

func New() *Resolver {
	return &Resolver{timeout: 3 * time.Second}
}

func (r *Resolver) Resolve(name string, qtype uint16) ([]dns.Record, error) {
	return r.resolve(name, qtype, rootServers[0], 0)
}

func (r *Resolver) resolve(name string, qtype uint16, ns string, depth int) ([]dns.Record, error) {
	if depth > 10 {
		return nil, fmt.Errorf("too deep")
	}

	if r.Trace {
		fmt.Printf("%*s> %s %s @%s\n", depth*2, "", name, dns.TypeString(qtype), ns)
	}

	resp, err := r.query(ns, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", ns, err)
	}

	if len(resp.Answers) > 0 {
		for _, a := range resp.Answers {
			if a.Type == dns.TypeCNAME && qtype != dns.TypeCNAME {
				if r.Trace {
					fmt.Printf("%*s  CNAME -> %s\n", depth*2, "", a.DecodedName)
				}
				return r.resolve(a.DecodedName, qtype, rootServers[0], depth+1)
			}
		}
		return resp.Answers, nil
	}

	nextNS := ""
	for _, auth := range resp.Authority {
		if auth.Type != dns.TypeNS {
			continue
		}
		nsName := auth.DecodedName
		// check glue
		for _, extra := range resp.Extra {
			if extra.Type == dns.TypeA && extra.Name == nsName && len(extra.Data) == 4 {
				nextNS = net.IP(extra.Data).String()
				break
			}
		}
		if nextNS != "" {
			break
		}
		// resolve NS
		nsRecs, err := r.resolve(nsName, dns.TypeA, rootServers[0], depth+1)
		if err == nil && len(nsRecs) > 0 && len(nsRecs[0].Data) == 4 {
			nextNS = net.IP(nsRecs[0].Data).String()
			break
		}
	}

	if nextNS == "" {
		return nil, fmt.Errorf("stuck resolving %s, no NS found", name)
	}

	return r.resolve(name, qtype, nextNS, depth+1)
}

func (r *Resolver) query(server, name string, qtype uint16) (*dns.Response, error) {
	conn, err := net.DialTimeout("udp", server+":53", r.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.timeout))

	q := dns.BuildQuery(name, qtype)
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return dns.ParseResponse(buf[:n])
}
