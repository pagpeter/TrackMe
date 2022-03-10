package main

import (
	"log"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
	clover "github.com/ostafen/clover"
)

var Gja3 JA3Calculating

var cert tls.Certificate
var db *clover.DB
var c *Config = &Config{}

func init() {
	err := c.LoadFromFile()
	if err != nil {
		log.Fatal(err)
	}
	if c.LogToDB {
		db, _ = clover.Open("requests-db")
		db.CreateCollection("requests")
	}
}

func main() {
	log.Println("Starting server...")
	log.Println("Listening on " + c.Host + c.TLSPort)

	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}
	// Create a TLS configuration
	config := tls.Config{
		ServerName: c.Host,
		NextProtos: []string{
			// "http/1.0",
			//	"http/1.1",
			"h2",
		},
		//InsecureSkipVerify: true,
		GetCertificate: FingerprintMSG,
	}

	// Start listening
	listener, err := tls.Listen("tcp", c.Host+c.TLSPort, &config)
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
