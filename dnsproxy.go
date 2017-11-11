package main

// https://godoc.org/github.com/miekg/dns

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
	// "strconv"
	"encoding/json"
	"io/ioutil"
	"strings"
)

type Options struct {
	Dnsserver string `short:"d" long:"dnsserver" env:"DNSSERVER" default:"8.8.8.8" description:"Public DNS server"`
	Dnsport   string `long:"dnsport" env:"DNSPORT" default:"53" description:"Public DNS server port"`
	Port      string `short:"p" long:"listenport" env:"LISTENPORT" default:"53" description:"Port where this service is listen to"`
	Loglevel  string `long:"loglevel" env:"LOGLEVEL" default:"info" description:"loglevel" choice:"warn" choice:"info" choice:"debug"`
	Version   bool   `long:"version" short:"v" description:"show version"`
}

var opts Options

type zonefile struct {
	A map[string]string `json:"a"`
}

var records = map[string]string{
	"t.service.":         "1.0.0.1",
	"t2.service.":        "1.0.0.2",
	"centralinstall.":    "1.0.0.4",
	"centralinstall.tt.": "1.0.0.5",
	"icemaster.":         "10.77.77.11",
}

var version string = "0.1.0"
var records2 zonefile

func init() {
	_, err := flags.Parse(&opts)

	if err != nil {
		log.Error("Error in parsing arguments")
	}

	log.SetLevel(log.DebugLevel)

	file, err := ioutil.ReadFile("./records.json")

	if err != nil {
		log.Error("Fail to open file")
	}

	err = json.Unmarshal(file, &records2)

	if err != nil {
		log.Error("Fail to encode json")
	}
	litter.Dump(records2)

}

func query(zone string, qtype uint16) []dns.RR {
	// config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	var failresponse []dns.RR

	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(zone), qtype)
	m.SetEdns0(4096, true)

	// r, _, err := c.Exchange(m, "172.16.20.50:53")
	r, _, err := c.Exchange(m, opts.Dnsserver+":"+opts.Dnsport)

	if err != nil {
		log.Error("received non valid response")
		return failresponse
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Error("received non valid response")
		log.WithFields(log.Fields{
			"expected": dns.RcodeSuccess,
			"received": r.Rcode,
		}).Error("invalid Response code")
		return failresponse
	}

	for _, k := range r.Answer {
		if key, ok := k.(*dns.DNSKEY); ok {
			for _, alg := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
				fmt.Println("MARK ON")
				fmt.Printf("%s; %d\n", key.ToDS(alg).String(), key.Flags)
				fmt.Println("MARK OFF")
			}
		}
	}

	return r.Answer
}

func parseQuery(m *dns.Msg) {
	var header *dns.RR_Header
	logfields := log.Fields{}

	log.Info("parse query")

	for _, q := range m.Question {

		logfields["name"] = q.Name
		logfields["qtype"] = q.Qtype
		logfields["qclass"] = q.Qclass

		log.WithFields(logfields).Info("received dns.Question")
		switch q.Qtype {

		case dns.TypeA:

			ip := records2.A[q.Name]

			if ip == "" {
				shortname := strings.Split(q.Name, ".")[0]
				logfields["shortname"] = shortname
				log.WithFields(logfields).Debug("Full name not resolved local, query shortname")
				ip = records2.A[shortname+"."]
			}

			if ip == "" {
				log.WithFields(logfields).Debug("shortname not resolved local")
				delete(logfields, "shortname")

				log.WithFields(logfields).Info("start default query")
				m.Answer = query(q.Name, q.Qtype)
			} else {
				log.WithFields(logfields).Info("name intern resoloved to ", ip)
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					// Get the Header and set the Time to Live (ttl) to 10 Seconds
					// Changes can be pushed faster to the client with that ttl
					header = rr.Header()
					header.Ttl = 10
					m.Answer = append(m.Answer, rr)
				}
			}
		default:
			log.WithFields(logfields).Info("start default query")
			query(q.Name, q.Qtype)
			m.Answer = query(q.Name, q.Qtype)
		}
		logfields["answers"] = len(m.Answer)
		log.WithFields(logfields).Info("Resulting answer")

		// fmt.Printf("%T\n", m.Answer)

		// var s dns.A

		// answer1A := answer1.(dns.A)

		for idx, answer := range m.Answer {
			// fmt.Printf("%T\n", answer)

			// answer1 := answer.(*dns.A).A
			// litter.Dump(answer1.A)
			fmt.Println(answer.(*dns.A).A)

			// litter.Dump(m.Answer)
			// fmt.Printf("%T\n", m.Answer)
			// fmt.Printf("%T\n", m.Answer[0])

			// var s dns.A

			// s = answer.(dns.A)
			// litter.Dump(s)
			// litter.Dump(s.A)

			// litter.Dump(answer.(dns.A))
			// answer1 := &answer

			// fmt.Printf("\t\t%T\n", answer)
			// litter.Dump(answer1)
			logfields["answer_index"] = idx
			header = answer.Header()
			logfields["answer_name"] = header.Name
			logfields["answer_ttl"] = header.Ttl
			logfields["answer_rrtype"] = header.Rrtype
			if header.Rrtype == 1 {
				logfields["answer_ip"] = answer.(*dns.A).A

			}

			// bb := answer.(dns.A)
			// litter.Dump(bb)
			// if header.Rrtype == 1 {
			// 	fmt.Println((dns.A)answer).A
			// }
			log.WithFields(logfields).Debug(answer.String())

		}

		// fmt.Println(m.Answer[0])

		// fmt.Println(string(m.Answer[0]))
		// litter.Dump(m.Answer[0].A)
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.WithFields(log.Fields{
		"Opcode": r.Opcode,
	}).Info("handle query")

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
	dns.HandleFunc(".", handleDnsRequest)

	litter.Dump("USE")

	// start server
	// port := opts.Port
	server := &dns.Server{Addr: ":" + opts.Port, Net: "udp"}
	log.WithFields(log.Fields{
		"port":     opts.Port,
		"fwdhost":  opts.Dnsserver,
		"fwdport":  opts.Dnsport,
		"loglevel": opts.Loglevel,
		"version":  version,
	}).Info("Starting Service")

	log.Printf("Starting at %v\n", opts.Port)

	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
