package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/pagpeter/quic-go"
	"github.com/pagpeter/quic-go/http3"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/tcp"
	"github.com/pagpeter/trackme/pkg/utils"
	utls "github.com/wwhtrbbtt/utls"
)

var cert tls.Certificate
var utlsCert utls.Certificate
var srv *server.Server
var local = false

func logCrash(r interface{}) {
	crashInfo := fmt.Sprintf("PANIC: %v\n", r)
	crashInfo += fmt.Sprintf("Time: %v\n", time.Now().Format(time.RFC3339))

	// Get stack trace
	buf := make([]byte, 1024*1024)
	n := runtime.Stack(buf, false)
	crashInfo += fmt.Sprintf("Stack trace:\n%s\n", buf[:n])
	crashInfo += "----------------------------------------\n\n"

	// Write to crashes.txt
	file, err := os.OpenFile("crashes.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening crashes.txt: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(crashInfo); err != nil {
		log.Printf("Error writing to crashes.txt: %v", err)
	}

	log.Printf("PANIC: %v", r)
	log.Println("Crash details written to crashes.txt")
}

func init() {
	// Initialize server and load config
	srv = server.NewServer()

	if err := srv.GetConfig().LoadFromFile(); err != nil {
		log.Fatal(err)
	}
}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, srv.GetConfig().HTTPRedirect, http.StatusMovedPermanently)
}

func StartRedirectServer(host, port string) {
	// Starts an HTTP server on port 80 that redirects to the HTTPS server on port 443

	local = host == "" && port != "443"
	srv.SetLocal(local)

	log.Println("Starting Redirect Server:", srv.GetConfig().HTTPRedirect)
	log.Println("Listening on", host+":"+port)

	http.HandleFunc("/", redirect)
	if err := http.ListenAndServe(host+":"+port, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// Timeout function
func timeoutHandleTLSConnection(conn net.Conn) error {
	result := make(chan error)
	go func() {
		result <- srv.HandleTLSConnection(conn)
	}()
	select {
	case <-time.After(15 * time.Second):
		return fmt.Errorf("connection timed out")
	case err := <-result:
		return err
	}
}

func StartHTTP3Server(host string, port int) {
	// Use the server's HTTP/3 handler
	handler := srv.HandleHTTP3()

	// Configure TLS for HTTP/3
	h3TLSConfig := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	})

	addr := fmt.Sprintf("%s:%d", host, port)

	h3Server := &http3.Server{
		Handler:   handler,
		Addr:      addr,
		TLSConfig: h3TLSConfig,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
		},
	}

	log.Println("Starting HTTP/3 server on", addr)
	if err := h3Server.ListenAndServe(); err != nil {
		log.Printf("HTTP/3 server error: %v", err)
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			logCrash(r)
			os.Exit(1)
		}
	}()

	log.Println("Starting server...")
	log.Println("Listening on " + srv.GetConfig().Host + ":" + srv.GetConfig().TLSPort)

	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(srv.GetConfig().CertFile, srv.GetConfig().KeyFile)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}

	// Convert standard TLS cert to utls cert
	utlsCert = utls.Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  cert.PrivateKey,
		Leaf:        cert.Leaf,
	}

	// Create a TLS configuration
	config := utls.Config{
		ServerName: srv.GetConfig().Host,
		NextProtos: []string{
			"h2",
		},
		Certificates: []utls.Certificate{utlsCert},
	}

	listener, err := utls.Listen("tcp", srv.GetConfig().Host+":"+srv.GetConfig().TLSPort, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	tlsPort, err := strconv.Atoi(srv.GetConfig().TLSPort)
	if err != nil {
		log.Fatal("Error parsing tls port", err)
	}

	defer listener.Close()
	go StartRedirectServer(srv.GetConfig().Host, srv.GetConfig().HTTPPort)
	if srv.GetConfig().EnableQUIC {
		go StartHTTP3Server(srv.GetConfig().Host, tlsPort)
	}
	if srv.GetConfig().Device != "" {
		go tcp.SniffTCP(srv.GetConfig().Device, tlsPort, srv)
	}

	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logCrash(r)
					log.Println("Recovered from panic in main loop, continuing to serve requests")
				}
			}()

			conn, err := listener.Accept()
			if err != nil {
				log.Println("Error accepting connection", err)
				return
			}
			var ip string
			if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				ip = addr.IP.String()
			}
			if utils.IsIPBlocked(ip) {
				server.Log("Request from IP " + ip + " blocked")
				if _, err := conn.Write([]byte("Don't waste proxies")); err != nil {
					log.Println("Error writing to blocked connection:", err)
				}
				if err := conn.Close(); err != nil {
					log.Println("Error closing blocked connection:", err)
				}
			} else {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							logCrash(r)
							log.Printf("Recovered from panic in connection handler for IP %s", ip)
							if err := conn.Close(); err != nil {
								log.Println("Error closing connection after panic:", err)
							}
						}
					}()

					if err := timeoutHandleTLSConnection(conn); err != nil {
						server.Log(fmt.Sprintf("Request failed for %s: %v", ip, err))
						if err := conn.Close(); err != nil {
							log.Println("Error closing failed connection:", err)
						}
					}
				}()
			}
		}()
	}
}
