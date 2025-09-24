package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/tcp"
	"github.com/pagpeter/trackme/pkg/utils"
	tls "github.com/wwhtrbbtt/utls"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var cert tls.Certificate
var srv *server.Server
var local = false

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

func main() {
	log.Println("Starting server...")
	log.Println("Listening on " + srv.GetConfig().Host + ":" + srv.GetConfig().TLSPort)

	// Load the TLS certificates
	var err error
	cert, err = tls.LoadX509KeyPair(srv.GetConfig().CertFile, srv.GetConfig().KeyFile)
	if err != nil {
		log.Fatal("Error loading TLS certificates", err)
	}
	// Create a TLS configuration
	config := tls.Config{
		ServerName: srv.GetConfig().Host,
		NextProtos: []string{
			"h2",
		},
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", srv.GetConfig().Host+":"+srv.GetConfig().TLSPort, &config)
	if err != nil {
		log.Fatal("Error starting tcp listener", err)
	}

	tlsPort, err := strconv.Atoi(srv.GetConfig().TLSPort)
	if err != nil {
		log.Fatal("Error parsing tls port", err)
	}

	defer listener.Close()
	go StartRedirectServer(srv.GetConfig().Host, srv.GetConfig().HTTPPort)
	if srv.GetConfig().Device != "" {
		go tcp.SniffTCP(srv.GetConfig().Device, tlsPort, srv)
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
		if utils.IsIPBlocked(ip) {
			server.Log("Request from IP " + ip + " blocked")
			conn.Write([]byte("Don't waste proxies"))
			conn.Close()
		} else {
			go func() {
				success := timeoutHandleTLSConnection(conn)
				if !success {
					server.Log("Request aborted - " + ip)
					conn.Close()
				}
			}()
		}

	}

}
