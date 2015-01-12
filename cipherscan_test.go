package main

import (
	"testing"

	"github.com/jacobhaven/cipherscan/tls"
)

var ciphers = cipherIDsFromMap(tls.CipherSuites)

func BenchmarkCipherscan(b *testing.B) {
	skipVerify = true
	kwise = 30
	for i := 0; i < b.N; i++ {
		sorted := make(chan cID, len(tls.CipherSuites))
		recursiveScanSite("54.169.0.198:4444", ciphers, sorted)
	}
}
