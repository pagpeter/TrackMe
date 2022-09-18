package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	tls "github.com/wwhtrbbtt/utls"

	// 	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var cert tls.Certificate
var c *Config = &Config{}

var collection *mongo.Collection
var ctx = context.TODO()
var client *mongo.Client

var local = false

func init() {
	// Loads the config and connects to database (if enabled)

	err := c.LoadFromFile()
	if err != nil {
		log.Fatal(err)
	}
	clientOptions := options.Client().ApplyURI(c.MongoURL)
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	collection = client.Database("TrackMe").Collection("requests")

	_, err = collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		})
	if err != nil {
		log.Println(err)
	}

}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://tls.peet.ws", 301)
}

func StartRedirectServer(host, port string) {
	// Starts a HTTP server on port 80 that redirects to the HTTPS server on port 443

	local = host == "" && port != "443"

	log.Println("Starting Redirect Server")
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
	log.Println("Listening on " + c.Host + ":" + c.TLSPort)

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
			"h2",
		},
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", c.Host+":"+c.TLSPort, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	defer listener.Close()
	go StartRedirectServer(c.Host, c.HTTPPort)

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
			fmt.Println("Request from IP", ip, "blocked")
			conn.Write([]byte("Don't waste proxies"))
			conn.Close()
		} else {
			go func() {
				success := timeoutHandleTLSConnection(conn)
				if !success {
					log.Println("Request aborted")
					conn.Close()
				}
			}()
		}

	}

}
