package main

import (
	"log"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
	c "github.com/ostafen/clover"
)

const port = ":443"
const host = ""
const TLScert = "cert.pem"
const TLSkey = "key.pem"

var Gja3 JA3Calculating

var cert tls.Certificate
var db *c.DB

func init() {
	db, _ = c.Open("requests-db")
	db.CreateCollection("requests")
}

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
		ServerName: host,
		NextProtos: []string{
			// "http/1.0",
			//	"http/1.1",
			"h2",
		},
		//InsecureSkipVerify: true,
		GetCertificate: FingerprintMSG,
	}

	// Start listening
	listener, err := tls.Listen("tcp", host+port, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	defer listener.Close()

	go StartRedirectServer()

	// Listen for connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection", err)
		}
		go handleConnection(conn)
	}

}
