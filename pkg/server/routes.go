package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

func staticFile(file string) func(types.Response, url.Values) ([]byte, string) {
	return func(types.Response, url.Values) ([]byte, string) {
		b, _ := utils.ReadFile(file)
		return b, "text/html"
	}
}

func apiAll(res types.Response, _ url.Values) ([]byte, string) {
	return []byte(res.ToJson()), "application/json"
}

func apiTLS(res types.Response, _ url.Values) ([]byte, string) {
	return []byte(types.Response{
		TLS: res.TLS,
	}.ToJson()), "application/json"
}

func apiClean(res types.Response, _ url.Values) ([]byte, string) {
	akamai := "-"
	hash := "-"
	if res.HTTPVersion == "h2" {
		akamai = res.Http2.AkamaiFingerprint
		hash = utils.GetMD5Hash(res.Http2.AkamaiFingerprint)
	}
	return []byte(types.SmallResponse{
		JA3:           res.TLS.JA3,
		JA3Hash:       res.TLS.JA3Hash,
		JA4:           res.TLS.JA4,
		JA4_r:         res.TLS.JA4_r,
		Akamai:        akamai,
		AkamaiHash:    hash,
		PeetPrint:     res.TLS.PeetPrint,
		PeetPrintHash: res.TLS.PeetPrintHash,
	}.ToJson()), "application/json"
}

func apiRequestCount(srv *Server) func(types.Response, url.Values) ([]byte, string) {
	return func(_ types.Response, _ url.Values) ([]byte, string) {
		if !srv.IsConnectedToDB() {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		return []byte(fmt.Sprintf(`{"total_requests": %v}`, GetTotalRequestCount(srv))), "application/json"
	}
}

func apiSearchJA3(srv *Server) func(types.Response, url.Values) ([]byte, string) {
	return func(_ types.Response, u url.Values) ([]byte, string) {
		if !srv.IsConnectedToDB() {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		by := utils.GetParam("by", u)
		if by == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByJa3(by, srv)
		j, _ := json.MarshalIndent(res, "", "\t")
		return j, "application/json"
	}
}

func apiSearchH2(srv *Server) func(types.Response, url.Values) ([]byte, string) {
	return func(_ types.Response, u url.Values) ([]byte, string) {
		if !srv.IsConnectedToDB() {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		by := utils.GetParam("by", u)
		if by == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByH2(by, srv)
		j, _ := json.MarshalIndent(res, "", "\t")
		return j, "application/json"
	}
}

func apiSearchPeetPrint(srv *Server) func(types.Response, url.Values) ([]byte, string) {
	return func(_ types.Response, u url.Values) ([]byte, string) {
		if !srv.IsConnectedToDB() {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		by := utils.GetParam("by", u)
		if by == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByPeetPrint(by, srv)
		j, _ := json.MarshalIndent(res, "", "\t")
		return j, "application/json"
	}
}

func apiSearchUserAgent(srv *Server) func(types.Response, url.Values) ([]byte, string) {
	return func(_ types.Response, u url.Values) ([]byte, string) {
		if !srv.IsConnectedToDB() {
			return []byte("{\"error\": \"Not connected to database.\"}"), "application/json"
		}
		by := utils.GetParam("by", u)
		if by == "" {
			return []byte("{\"error\": \"No 'by' param present\"}"), "application/json"
		}
		res := GetByUserAgent(by, srv)
		j, _ := json.MarshalIndent(res, "", "\t")
		return j, "application/json"
	}
}

func index(r types.Response, v url.Values) ([]byte, string) {
	res, ct := staticFile("static/index.html")(r, v)
	data, _ := json.Marshal(r)
	return []byte(strings.ReplaceAll(string(res), "/*DATA*/", string(data))), ct
}

func getAllPaths(srv *Server) map[string]func(types.Response, url.Values) ([]byte, string) {
	return map[string]func(types.Response, url.Values) ([]byte, string){
		"/":                     index,
		"/explore":              staticFile("static/explore.html"),
		"/api/all":              apiAll,
		"/api/tls":              apiTLS,
		"/api/clean":            apiClean,
		"/api/request-count":    apiRequestCount(srv),
		"/api/search-ja3":       apiSearchJA3(srv),
		"/api/search-h2":        apiSearchH2(srv),
		"/api/search-peetprint": apiSearchPeetPrint(srv),
		"/api/search-useragent": apiSearchUserAgent(srv),
	}
}
