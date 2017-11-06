package main

// https://godoc.org/github.com/miekg/dns

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
	"strconv"
	"strings"
)

var records = map[string]string{
	"t.service.":         "1.0.0.1",
	"t2.service.":        "1.0.0.2",
	"centralinstall.":    "1.0.0.4",
	"centralinstall.tt.": "1.0.0.5",
}

func query(zone string, qtype uint16) []dns.RR {
	// config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	var fakeresponse []dns.RR
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), qtype)
	m.SetEdns0(4096, true)
	// litter.Dump(m)
	r, _, err := c.Exchange(m, "172.16.20.50:53")
	// fmt.Println("RESULT:")

	// litter.Dump(r)
	// fmt.Println("YYYYYYYYYYYYYYYY")

	// log.WithFields(log.Fields{
	// 	"name":   q.Name,
	// 	"qtype":  q.Qtype,
	// 	"qclass": q.Qclass,
	// }).Info("received dns.Question")

	if err != nil {
		log.Error("received non valid response")
		return fakeresponse
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Error("received non valid response")
		log.WithFields(log.Fields{
			"expected": dns.RcodeSuccess,
			"received": r.Rcode,
		}).Error("invalid Response code")
		return fakeresponse
	}

	for _, k := range r.Answer {
		if key, ok := k.(*dns.DNSKEY); ok {
			for _, alg := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
				fmt.Printf("%s; %d\n", key.ToDS(alg).String(), key.Flags)
			}
		}
	}
	return r.Answer
}

func parseQuery(m *dns.Msg) {
	log.Info("parse query")
	for _, q := range m.Question {
		log.WithFields(log.Fields{
			"name":   q.Name,
			"qtype":  q.Qtype,
			"qclass": q.Qclass,
		}).Info("received dns.Question")
		switch q.Qtype {
		case dns.TypeA:

			ip := records[q.Name]

			if ip == "" {
				singlename := strings.Split(q.Name, ".")[0]
				fmt.Printf("SINGLENAME: %v\n", singlename)
				log.Info("havent found the direct name, query first section")
				ip = records[singlename+"."]
			}

			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}

				// litter.Dump(m.Answer[0].Hdr.Ttl)
				log.WithFields(log.Fields{"entrys found": len(m.Answer)}).Info("answer")

			} else {
				query(q.Name, q.Qtype)
				// rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				m.Answer = query(q.Name, q.Qtype)
				log.WithFields(log.Fields{"entrys found": len(m.Answer)}).Info("answer")

				litter.Dump(m.Answer)

			}
		default:
			log.Info("no type defined, default query")
			query(q.Name, q.Qtype)
			// rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
			m.Answer = query(q.Name, q.Qtype)
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.WithFields(log.Fields{
		"Opcode": r.Opcode,
	}).Info("handle query")

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// litter.Dump(m)
	// litter.Dump(r)

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {
	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)
	dns.HandleFunc(".", handleDnsRequest)

	litter.Dump("USE")

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
