package server

import (
	"context"
	"strings"
	"sync"

	"github.com/pagpeter/trackme/pkg/types"
	"go.mongodb.org/mongo-driver/mongo"
)

// State holds all the global state previously scattered across the application
type State struct {
	Config          *types.Config
	ConnectedToDB   bool
	TCPFingerprints sync.Map
	MongoClient     *mongo.Client
	MongoCollection *mongo.Collection
	MongoContext    context.Context
	Local           bool
}

// Server provides access to shared state and functionality
type Server struct {
	State *State
}

// NewServer creates a new server instance with initialized state
func NewServer() *Server {
	return &Server{
		State: &State{
			Config:          &types.Config{},
			ConnectedToDB:   false,
			TCPFingerprints: sync.Map{},
			MongoContext:    context.TODO(),
		},
	}
}

// GetConfig returns the loaded configuration
func (s *Server) GetConfig() *types.Config {
	return s.State.Config
}

// IsConnectedToDB returns whether the database connection is active
func (s *Server) IsConnectedToDB() bool {
	return s.State.ConnectedToDB
}

// GetTCPFingerprints returns the TCP fingerprints map
func (s *Server) GetTCPFingerprints() *sync.Map {
	return &s.State.TCPFingerprints
}

// GetMongoCollection returns the MongoDB collection
func (s *Server) GetMongoCollection() *mongo.Collection {
	return s.State.MongoCollection
}

// GetMongoContext returns the MongoDB context
func (s *Server) GetMongoContext() context.Context {
	return s.State.MongoContext
}

// SetMongoConnection sets the database connection details
func (s *Server) SetMongoConnection(client *mongo.Client, collection *mongo.Collection) {
	s.State.MongoClient = client
	s.State.MongoCollection = collection
	s.State.ConnectedToDB = true
}

// GetAdmin returns the CORS key configuration
func (s *Server) GetAdmin() (string, bool) {
	return s.State.Config.CorsKey, s.State.Config.CorsKey != ""
}

// GetUserAgent extracts the user agent from a response
func GetUserAgent(res types.Response) string {
	var headers []string
	var ua string

	if res.HTTPVersion == "h2" {
		return res.UserAgent
	} else {
		if res.Http1 == nil {
			return ""
		}
		headers = res.Http1.Headers
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent: ") {
			ua = strings.Split(header, ": ")[1]
		}
	}

	return ua
}

// SetLocal sets the local development flag
func (s *Server) SetLocal(local bool) {
	s.State.Local = local
}

// IsLocal returns whether we're running in local development mode
func (s *Server) IsLocal() bool {
	return s.State.Local
}