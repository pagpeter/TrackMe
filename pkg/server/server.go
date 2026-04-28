package server

import (
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

type State struct {
	Config       *types.Config
	Fingerprints *FingerprintStore
	Local        bool
}

type Server struct {
	State *State
}

func NewServer() *Server {
	return &Server{
		State: &State{
			Config:       &types.Config{},
			Fingerprints: NewFingerprintStore(),
		},
	}
}

func (s *Server) GetConfig() *types.Config {
	return s.State.Config
}

func (s *Server) GetFingerprints() *FingerprintStore {
	return s.State.Fingerprints
}

func (s *Server) GetAdmin() (string, bool) {
	return s.State.Config.CorsKey, s.State.Config.CorsKey != ""
}

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

func (s *Server) SetLocal(local bool) {
	s.State.Local = local
}

func (s *Server) IsLocal() bool {
	return s.State.Local
}
