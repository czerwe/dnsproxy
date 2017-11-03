package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
)

var records = map[string]string{
	"test.service.":  "192.168.0.2",
	"test3.service.": "192.168.0.1",
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
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
