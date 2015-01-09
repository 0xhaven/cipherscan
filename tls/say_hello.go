package tls

import (
	"errors"
	"io"
	"net"
)

// SayHello sends a simple Client Hello to server and returns the negotiated ciphersuite ID
func SayHello(conn net.Conn, config *Config) (uint16, error) {
	c := &Conn{conn: conn, config: config}
	hello := &clientHelloMsg{
		vers:                c.config.maxVersion(),
		compressionMethods:  []uint8{compressionNone},
		random:              make([]byte, 32),
		ocspStapling:        true,
		serverName:          c.config.ServerName,
		supportedCurves:     c.config.curvePreferences(),
		supportedPoints:     []uint8{pointFormatUncompressed},
		nextProtoNeg:        len(c.config.NextProtos) > 0,
		secureRenegotiation: true,
		cipherSuites:        c.config.cipherSuites(),
	}

	_, err := io.ReadFull(c.config.rand(), hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return 0, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		// TODO: enumerate all possible signatures and hashes
		hello.signatureAndHashes = supportedSKXSignatureAlgorithms
	}

	c.writeRecord(recordTypeHandshake, hello.marshal())

	msg, err := c.readHandshake()
	if err != nil {
		return 0, err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return 0, unexpectedMessageError(serverHello, msg)
	}

	return serverHello.cipherSuite, nil
}
