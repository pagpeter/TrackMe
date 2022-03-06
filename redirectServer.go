package main

import (
	"log"
	"net"
)

func handleRedirectConnection(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: https://tls.peet.ws\r\n\r\n"))
	conn.Close()
}

func StartRedirectServer() {
	log.Println("Starting Redirect Server")

	// Start listening
	log.Println("Listening on :80")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()

	for {
		conn, err := ln.Accept()
		log.Println("Redirect: Accepted connection", conn.RemoteAddr())
		if err != nil {
			conn.Close()
			log.Println("Error accepting connection", err)
		}
		go handleRedirectConnection(conn)
	}
}
