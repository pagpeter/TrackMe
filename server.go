package main

import (
	"log"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

const port = ":443"
const host = "localhost"
const TLScert = "cert.pem"
const TLSkey = "key.pem"

var Channel = make(chan JA3Calculating)

var cert tls.Certificate

func main() {
	log.Println("Starting server...")
	log.Println("Listening on " + host + port)

	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(TLScert, TLSkey)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}
	// Create a TLS configuration
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   host,
		NextProtos: []string{
			"http/1.1",
			"h2",
		},
		InsecureSkipVerify: true,
		GetCertificate:     FingerprintMSG,
	}

	// Start listening
	listener, err := tls.Listen("tcp", host+port, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	defer listener.Close()

	// Listen for connections

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection", err)
		}

		go handleConnection(conn)
	}

}
