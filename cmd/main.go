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

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	err := srv.GetConfig().LoadFromFile()
	if err != nil {
		log.Fatal(err)
	}

	if len(srv.GetConfig().MongoURL) == 0 { // Don't attempt to setup mongo if its not populated in the config
		return
	}

	clientOptions := options.Client().ApplyURI(srv.GetConfig().MongoURL)
	client, err := mongo.Connect(srv.GetMongoContext(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(srv.GetMongoContext(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(srv.GetConfig().DB, srv.GetConfig().Collection)
	collection := client.Database(srv.GetConfig().DB).Collection(srv.GetConfig().Collection)
	srv.SetMongoConnection(client, collection)
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
	err := http.ListenAndServe(host+":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// Timeout function
func timeoutHandleTLSConnection(conn net.Conn) bool {
	result := make(chan bool)
	go func() {
		result <- srv.HandleTLSConnection(conn)
	}()
	select {
	case <-time.After(15 * time.Second):
		return false
	case tmp := <-result:
		return tmp
	}
}

func StartHTTP3Server(host, port string) {
	// Use the server's HTTP/3 handler
	handler := srv.HandleHTTP3()

	// Configure TLS for HTTP/3
	h3TLSConfig := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	})

	h3Server := &http3.Server{
		Handler:   handler,
		Addr:      host + ":" + port,
		TLSConfig: h3TLSConfig,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
		},
	}

	log.Println("Starting HTTP/3 server on", host+":"+port)
	err := h3Server.ListenAndServe()
	if err != nil {
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
	go StartHTTP3Server(srv.GetConfig().Host, srv.GetConfig().TLSPort)
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
			//fmt.Println(reflect.TypeOf(conn))
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
				conn.Write([]byte("Don't waste proxies"))
				conn.Close()
			} else {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							logCrash(r)
							log.Printf("Recovered from panic in connection handler for IP %s", ip)
							conn.Close()
						}
					}()

					success := timeoutHandleTLSConnection(conn)
					if !success {
						server.Log("Request aborted - " + ip)
						conn.Close()
					}
				}()
			}
		}()
	}

}
