package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	tls "github.com/wwhtrbbtt/utls"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var cert tls.Certificate
var LoadedConfig *Config = &Config{}
var collection *mongo.Collection
var ctx = context.TODO()
var client *mongo.Client
var local = false
var connectedToDB = false
var TCPFingerprints sync.Map

func init() {
	// Loads the config and connects to database (if enabled)

	err := LoadedConfig.LoadFromFile()
	if err != nil {
		log.Fatal(err)
	}

	if len(LoadedConfig.MongoURL) == 0 { // Don't attempt to setup mongo if its not populated in the config
		return
	}

	clientOptions := options.Client().ApplyURI(LoadedConfig.MongoURL)
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(LoadedConfig.DB, LoadedConfig.Collection)
	collection = client.Database(LoadedConfig.DB).Collection(LoadedConfig.Collection)
	connectedToDB = true

}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, LoadedConfig.HTTPRedirect, http.StatusMovedPermanently)
}

func StartRedirectServer(host, port string) {
	// Starts an HTTP server on port 80 that redirects to the HTTPS server on port 443

	local = host == "" && port != "443"

	log.Println("Starting Redirect Server:", LoadedConfig.HTTPRedirect)
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
		result <- HandleTLSConnection(conn)
	}()
	select {
	case <-time.After(15 * time.Second):
		return false
	case tmp := <-result:
		return tmp
	}
}

func main() {
	log.Println("Starting server...")
	log.Println("Listening on " + LoadedConfig.Host + ":" + LoadedConfig.TLSPort)

	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(LoadedConfig.CertFile, LoadedConfig.KeyFile)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}
	// Create a TLS configuration
	config := tls.Config{
		ServerName: LoadedConfig.Host,
		NextProtos: []string{
			"h2",
		},
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", LoadedConfig.Host+":"+LoadedConfig.TLSPort, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	tlsPort, err := strconv.Atoi(LoadedConfig.TLSPort)
	if err != nil {
		log.Fatal("Error parsing tls port", err)
	}

	defer listener.Close()
	go StartRedirectServer(LoadedConfig.Host, LoadedConfig.HTTPPort)
	if LoadedConfig.Device != "" {
		go sniffTCP(LoadedConfig.Device, tlsPort)
	}

	for {
		conn, err := listener.Accept()
		//fmt.Println(reflect.TypeOf(conn))
		if err != nil {
			log.Println("Error accepting connection", err)
		}
		var ip string
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ip = addr.IP.String()
		}
		if IsIPBlocked(ip) {
			Log("Request from IP " + ip + " blocked")
			conn.Write([]byte("Don't waste proxies"))
			conn.Close()
		} else {
			go func() {
				success := timeoutHandleTLSConnection(conn)
				if !success {
					Log("Request aborted - " + ip)
					conn.Close()
				}
			}()
		}

	}

}
