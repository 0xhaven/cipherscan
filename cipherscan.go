package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
)

var cSuites = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}

var cSuiteNames = []string{
	"TLS_RSA_WITH_RC4_128_SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
}

func scanSite(host, name string, cs uint16) error {
	config := &tls.Config{
		ServerName:         name,
		CipherSuites:       []uint16{cs},
		InsecureSkipVerify: noVerify,
	}

	conn, err := tls.Dial("tcp", host+":443", config)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

var noVerify bool

func main() {
	var verbose bool
	var hostName string
	flag.StringVar(&hostName, "h", "", "override the host name used")
	flag.BoolVar(&noVerify, "noverify", false, "don't verify host certificate")
	flag.BoolVar(&verbose, "v", false, "print any errors returned")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "No hosts specified.\n")
		os.Exit(1)
	}

	for _, host := range flag.Args() {
		name := hostName
		if name == "" {
			name = host
		}

		for i, cs := range cSuites {
			err := scanSite(host, name, cs)
			fmt.Printf("%s: ", cSuiteNames[i])
			if err == nil {
				fmt.Println("OK")
			} else {
				if verbose {
					fmt.Printf("FAILED (%v)\n", err)
				} else {
					fmt.Println("FAILED")
				}
			}
		}
	}
}
