package main

// https://godoc.org/github.com/miekg/dns
// https://github.com/miekg/dns/blob/master/types.go#L624

import (
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
	log "github.com/sirupsen/logrus"
	"gopkg.in/gemnasium/logrus-graylog-hook.v2"
	"io/ioutil"
	"strings"
)

type Options struct {
	Grayloghost string `long:"gelfhost" env:"GELFHOST" default:"" description:"Listening Graylog HOST"`
	Graylogport int    `long:"gelfport" env:"GELFPORT" default:"12201" description:"Listening port of Graylogs GELF UDP Input"`
	Dnsserver   string `short:"d" long:"dnsserver" env:"DNSSERVER" default:"8.8.8.8" description:"Public DNS server"`
	Dnsport     string `long:"dnsport" env:"DNSPORT" default:"53" description:"Public DNS server port"`
	Port        string `short:"p" long:"listenport" env:"LISTENPORT" default:"53" description:"Port where this service is listen to"`
	Loglevel    string `long:"loglevel" env:"LOGLEVEL" default:"info" description:"loglevel" choice:"warn" choice:"info" choice:"debug"`
	Version     bool   `long:"version" short:"v" description:"show version"`
}

var opts Options

type zonefile struct {
	A map[string]string `json:"a"`
}

var version string = "0.1.0"
var records zonefile

func init() {
	_, err := flags.Parse(&opts)

	if err != nil {
		log.Panic("Error in parsing arguments")
	}

	log.SetLevel(log.DebugLevel)

	file, err := ioutil.ReadFile("./records.json")

	if err != nil {
		log.Error("Fail to open file")
	}

	err = json.Unmarshal(file, &records)

	if err != nil {
		log.Error("Fail to encode json")
	}

	graylogFields := log.Fields{
		"app":     "desktopdns",
		"version": version,
	}

	var level log.Level
	switch opts.Loglevel {
	case "info":
		level = log.InfoLevel
	case "warn":
		level = log.WarnLevel
	case "debug":
		level = log.DebugLevel
	default:
		level = log.DebugLevel
	}

	log.SetLevel(level)

	if len(opts.Grayloghost) > 0 {
		hook := graylog.NewAsyncGraylogHook(fmt.Sprintf("%v:%v", opts.Grayloghost, opts.Graylogport), graylogFields)
		defer hook.Flush()
		log.AddHook(hook)
		log.Debug(fmt.Sprintf("Graylog reporting Enabled to host %v:%v", opts.Grayloghost, opts.Graylogport))
	} else {
		log.Debug("Graylog reporting disabled")
	}

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

			ip := records.A[q.Name]

			if ip == "" {
				shortname := strings.Split(q.Name, ".")[0]
				logfields["shortname"] = shortname
				log.WithFields(logfields).Debug("Full name not resolved local, query shortname")
				ip = records.A[shortname+"."]
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

		for idx, answer := range m.Answer {

			logfields["answer_index"] = idx
			header = answer.Header()
			logfields["answer_name"] = header.Name
			logfields["answer_ttl"] = header.Ttl
			logfields["answer_rrtype"] = header.Rrtype

			switch header.Rrtype {
			case dns.TypeA:
				logfields["answer_iptype"] = "ipv4"
				logfields["answer_ip"] = answer.(*dns.A).A
			case dns.TypeAAAA:
				logfields["answer_iptype"] = "ipv6"
				logfields["answer_ip"] = answer.(*dns.AAAA).AAAA
			case dns.TypeCNAME:
				logfields["answer_target"] = answer.(*dns.CNAME).Target
			default:
				litter.Dump(answer)
			}

			log.WithFields(logfields).Debug(answer.String())
			delete(logfields, "answer_iptype")

		}

	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {

	// litter.Dump(r)
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
