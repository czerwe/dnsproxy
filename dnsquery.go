package main

import (
	"fmt"
	// "log"
	// "strconv"

	"github.com/miekg/dns"
	"github.com/sanity-io/litter"
)

func main() {
	// config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	m := new(dns.Msg)
	zone := "test3.service"
	m.SetQuestion(dns.Fqdn(zone), dns.TypeA)
	m.SetEdns0(4096, true)
	litter.Dump(m)
	r, _, err := c.Exchange(m, "localhost:53")
	fmt.Println("RESULT:")
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
