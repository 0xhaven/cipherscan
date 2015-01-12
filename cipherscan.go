package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/jacobhaven/cipherscan/tls"
)

var (
	scanCount  int
	maxDepth   int
	totalFound int
)

func scanSite(host string, ciphers []uint16) (uint16, int, error) {
	scanCount++
	if verbose {
		fmt.Printf("Scan %d of %d ciphers\n", scanCount, len(ciphers))
	}
	config := &tls.Config{
		CipherSuites:       ciphers,
		InsecureSkipVerify: skipVerify,
	}
	if serverName != "" {
		config.ServerName = serverName
	}
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return 0, scanCount, err
	}
	defer conn.Close()
	serverCipher, err := tls.SayHello(conn, config)
	if err != nil {
		return 0, scanCount, err
	}
	for _, cipherID := range ciphers {
		if serverCipher == cipherID {
			return serverCipher, scanCount, nil
		}
	}
	return 0, scanCount, errors.New("Server negotiated ciphersuite we didn't send.")

}

type cIDs struct {
	ciphers []uint16
	depth   int
}
type cID struct {
	cipherID uint16
	depth    int
	scans    []int
}

func splitCIDs(c cIDs, kwise int) []cIDs {
	ret := make([]cIDs, 0, kwise)
	n := len(c.ciphers)
	var start, i int
	for end := n%kwise + n/kwise; start < n; end += n / kwise {
		if end > n {
			end = n
		}
		ret = append(ret, cIDs{c.ciphers[start:end], c.depth})
		i++
		start = end
	}
	return ret
}

func recursiveScanSite(host string, c cIDs, sorted chan cID) {
	defer close(sorted)
	if len(c.ciphers) == 0 {
		return
	}
	cipherID, scan, err := scanSite(host, c.ciphers)
	if err != nil {
		return
	}
	c.depth++
	sorted <- cID{cipherID, c.depth, []int{scan}}
	for i, id := range c.ciphers {
		if id == cipherID {
			c.ciphers[0], c.ciphers[i] = c.ciphers[i], c.ciphers[0]
			c.ciphers = c.ciphers[1:]
			break
		}
	}
	allCases := make([]reflect.SelectCase, 0, kwise)
	results := make([]chan cID, 0, kwise)
	for i, cs := range splitCIDs(c, kwise) {
		results = append(results, make(chan cID, len(cs.ciphers)))
		go recursiveScanSite(host, cs, results[i])
		allCases = append(allCases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(results[i])})
	}
	cases := allCases
	candidates := make([]cID, 0, len(cases))
	addedDepth := 0
	for {
		for len(cases) > 0 {
			chosen, recv, recvOK := reflect.Select(cases)
			cases[0], cases[chosen] = cases[chosen], cases[0]
			cases = cases[1:]
			if !recvOK {
				allCases = allCases[1:]
				continue
			}
			candidates = append(candidates, recv.Interface().(cID))
		}
		if len(candidates) > 1 {
			scandidates := make([]uint16, len(candidates))
			for i, cid := range candidates {
				scandidates[i] = cid.cipherID
			}
			cipherID, scan, err := scanSite(host, scandidates)
			if err != nil {
				panic(err)
			}
			addedDepth++
			for i, cid := range candidates {
				cid.scans = append(cid.scans, scan)
				if cipherID == cid.cipherID {
					cid.depth += addedDepth
					sorted <- cid
					candidates[0], candidates[i] = candidates[i], candidates[0]
					candidates = candidates[1:]
					start := len(allCases) - (i + 1)
					end := len(allCases) - i
					if start >= 0 {
						oldSelect := allCases[start]
						allCases = append(allCases[:start], allCases[end:]...)
						allCases = append(allCases, oldSelect)
						cases = allCases[len(allCases)-len(cases) : len(allCases)]
					}
					break
				}
			}
		} else {
			if len(candidates) == 1 {
				cid := candidates[0]
				cid.depth += addedDepth
				sorted <- cid
				for cid := range allCases[len(allCases)-1].Chan.Interface().(chan cID) {
					cid.depth += addedDepth
					sorted <- cid
				}
				return
			}
			if len(candidates) == 0 {
				return
			}
		}
	}
}
func cipherIDsFromMap(cipherMap map[uint16]string) cIDs {
	ciphers := make([]uint16, len(cipherMap))
	i := 0
	for cipherID := range cipherMap {
		ciphers[i] = cipherID
		i++
	}
	return cIDs{ciphers, 0}
}

var (
	skipVerify bool
	serverName string
	kwise      int
	verbose    bool
)

func main() {
	flag.BoolVar(&skipVerify, "skipverify", true, "skip verifying host certificate")
	flag.StringVar(&serverName, "servername", "", "server name for SNI")
	flag.IntVar(&kwise, "split", 2, "Breadth of concurrent subranches to create when recursively searching for ciphersuite ordering.")
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
		fmt.Printf("Scanning %s...\n", host)
		sorted := make(chan cID, len(tls.CipherSuites))
		ciphers := cipherIDsFromMap(tls.CipherSuites)
		recursiveScanSite(host, ciphers, sorted)
		fmt.Printf("%s supports these %d ciphersuites for a TLS 1.2–SSL 3 compatable client:\n", host, len(sorted))
		for c := range sorted {
			if verbose {
				fmt.Printf("Depth %d, Scans: %v", c.depth, c.scans)
			}
			fmt.Printf("\t0x%04x: %s\n", c.cipherID, tls.CipherSuites[c.cipherID])
		}
		if verbose {
			fmt.Printf("This scan required %d TLS dials\n", scanCount)
		}
	}
}
