package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/zachsplat/dns-resolver/pkg/dns"
)

var rootServers = []string{
	"198.41.0.4",   // a.root-servers.net
	"199.9.14.201", // b
	"192.33.4.12",  // c
	"199.7.91.13",  // d
}

type Resolver struct {
	Trace   bool
	timeout time.Duration
}

func New() *Resolver {
	return &Resolver{
		timeout: 3 * time.Second,
	}
}

func (r *Resolver) Resolve(name string, qtype uint16) ([]dns.Record, error) {
	// start from root
	nameserver := rootServers[0]
	return r.resolve(name, qtype, nameserver, 0)
}

func (r *Resolver) resolve(name string, qtype uint16, ns string, depth int) ([]dns.Record, error) {
	if depth > 10 {
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	if r.Trace {
		fmt.Printf("%*squery %s %s @%s\n", depth*2, "", name, dns.TypeString(qtype), ns)
	}

	resp, raw, err := r.query(ns, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("query to %s failed: %w", ns, err)
	}

	// got answers?
	if len(resp.Answers) > 0 {
		// check for CNAME
		for _, a := range resp.Answers {
			if a.Type == dns.TypeCNAME && qtype != dns.TypeCNAME {
				cname := decodeCname(raw, a)
				if r.Trace {
					fmt.Printf("%*sCNAME -> %s\n", depth*2, "", cname)
				}
				return r.resolve(cname, qtype, rootServers[0], depth+1)
			}
		}
		return resp.Answers, nil
	}

	// no answers, check authority for NS + glue
	nextNS := ""
	for _, auth := range resp.Authority {
		if auth.Type == dns.TypeNS {
			nsName := decodeNSName(raw, auth)
			// look for glue record
			for _, extra := range resp.Extra {
				if extra.Type == dns.TypeA && extra.Name == nsName {
					nextNS = net.IP(extra.Data).String()
					break
				}
			}
			if nextNS != "" {
				break
			}
			// no glue, need to resolve the NS name first
			nsRecords, err := r.resolve(nsName, dns.TypeA, rootServers[0], depth+1)
			if err == nil && len(nsRecords) > 0 {
				nextNS = net.IP(nsRecords[0].Data).String()
				break
			}
		}
	}

	if nextNS == "" {
		return nil, fmt.Errorf("no nameserver found for %s", name)
	}

	return r.resolve(name, qtype, nextNS, depth+1)
}

func (r *Resolver) query(server, name string, qtype uint16) (*dns.Response, []byte, error) {
	conn, err := net.DialTimeout("udp", server+":53", r.timeout)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.timeout))

	q := dns.BuildQuery(name, qtype)
	_, err = conn.Write(q)
	if err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}

	raw := buf[:n]
	resp, err := dns.ParseResponse(raw)
	return resp, raw, err
}

// these are gross but I need to decode names from rdata
// and the current DecodeName needs the full response buffer
func decodeCname(fullResp []byte, r dns.Record) string {
	// find where rdata starts in the full response and decode from there
	// this is hacky, need to refactor DecodeName
	for i := 0; i < len(fullResp)-len(r.Data); i++ {
		match := true
		for j := 0; j < len(r.Data); j++ {
			if fullResp[i+j] != r.Data[j] {
				match = false
				break
			}
		}
		if match {
			name, _ := dns.DecodeName(fullResp, i)
			return name
		}
	}
	return "(unknown)"
}

func decodeNSName(fullResp []byte, r dns.Record) string {
	return decodeCname(fullResp, r) // same logic
}
