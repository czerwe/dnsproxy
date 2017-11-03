package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
	"log"
	"strconv"
)

var records = map[string]string{
	"t.service.":  "1.0.0.1",
	"t2.service.": "1.0.0.2",
}

func query(zone string, qtype uint16) {
	// config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	m := new(dns.Msg)
	// zone := "test3.service"
	m.SetQuestion(dns.Fqdn(zone), qtype)
	m.SetEdns0(4096, true)
	// litter.Dump(m)
	r, _, err := c.Exchange(m, "localhost:5353")
	// fmt.Println("RESULT:")
	litter.Dump(r)
	if err != nil {
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		return
	}

	for _, k := range r.Answer {
		if key, ok := k.(*dns.DNSKEY); ok {
			for _, alg := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
				fmt.Printf("%s; %d\n", key.ToDS(alg).String(), key.Flags)
			}
		}
	}
}

func parseQuery(m *dns.Msg) {
	fmt.Println("handleQUERY")
	for _, q := range m.Question {
		litter.Dump(q)
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				query(q.Name, q.Qtype)
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("handleDNSR")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {
	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)

	// start server
	port := 53
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
