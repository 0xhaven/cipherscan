package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/jacobhaven/cipherscan/tls"
)

var scanCount int

func scanSite(host string, ciphers []uint16) (serverCipher uint16, err error) {
	scanCount++
	config := &tls.Config{
		CipherSuites:       ciphers,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS12,
	}
	if serverName != "" {
		config.ServerName = serverName
	}
	conn, err := net.Dial("tcp", host)
	if err != nil {
		if verbose {
			log.Println(err)
		}
		return
	}
	defer conn.Close()
	serverCipher, err = tls.SayHello(conn, config)
	if err != nil {
		if verbose {
			log.Println(err)
		}
		return
	}
	for _, cipherID := range ciphers {
		if serverCipher == cipherID {
			return
		}
	}
	log.Fatalln("Server negotiated ciphersuite we didn't send.")
	return
}
func recursiveScanSite(host string, ciphers []uint16, sorted chan uint16) {
	defer close(sorted)
	if len(ciphers) == 0 {
		return
	}
	cipherID, err := scanSite(host, ciphers)
	if err != nil {
		return
	}

	sorted <- cipherID
	for i := 0; i < len(ciphers); i++ {
		if ciphers[i] == cipherID {
			ciphers[0], ciphers[i] = ciphers[i], ciphers[0]
			ciphers = ciphers[1:]
			break
		}
	}
	left, right := make(chan uint16), make(chan uint16)
	go recursiveScanSite(host, ciphers[:len(ciphers)/2], left)
	go recursiveScanSite(host, ciphers[len(ciphers)/2:], right)
	var csLeft, csRight uint16
	leftOK, rightOK := true, true
	leftCh, rightCh := left, right
	nilCh := make(chan uint16)
	for leftOK && rightOK {
		if leftCh == rightCh {
			cipherID, err := scanSite(host, []uint16{csLeft, csRight})
			if err != nil {
				log.Fatalf("Error with known-good cipher suites (0x%x and 0x%x): %s\n", csLeft, csRight, err)
			}
			sorted <- cipherID
			switch cipherID {
			case csLeft:
				leftCh = left
			case csRight:
				rightCh = right
			}
		}
		select {
		case csLeft, leftOK = <-leftCh:
			leftCh = nilCh
		case csRight, rightOK = <-rightCh:
			rightCh = nilCh
		}
	}
	if leftOK {
		if leftCh == nilCh {
			sorted <- csLeft
		}
		for csLeft := range left {
			sorted <- csLeft
		}
	}
	if rightOK {
		if rightCh == nilCh {
			sorted <- csRight
		}
		for csRight := range right {
			sorted <- csRight
		}
	}
}
func cipherIDsFromMap(cipherMap map[uint16]string) []uint16 {
	ciphers := make([]uint16, len(cipherMap))
	i := 0
	for cipherID := range cipherMap {
		ciphers[i] = cipherID
		i++
	}
	return ciphers
}

var (
	skipVerify bool
	serverName string
	verbose    bool
)

func main() {
	flag.BoolVar(&skipVerify, "skipverify", true, "skip verifying host certificate")
	flag.StringVar(&serverName, "servername", "", "server name for SNI")
	flag.BoolVar(&verbose, "v", false, "print any errors returned")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "No hosts specified.\n")
		os.Exit(1)
	}
	for _, host := range flag.Args() {
		scanCount = 0
		if !strings.ContainsRune(host, ':') {
			host = host + ":443"
		}
		supported := make(chan uint16, len(tls.CipherSuites))
		ciphers := cipherIDsFromMap(tls.CipherSuites)
		recursiveScanSite(host, ciphers, supported)
		fmt.Printf("%s supports these %d ciphersuites for a TLS 1.2–SSL 3 compatable client:\n", host, len(supported))
		for cipherID := range supported {
			fmt.Printf("\t0x%04x: %s\n", cipherID, tls.CipherSuites[cipherID])
		}
		fmt.Printf("This scan required %d TLS dials\n", scanCount)
	}
}
