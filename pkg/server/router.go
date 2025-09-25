package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/tls"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

func Log(msg string) {
	t := time.Now()
	formatted := t.Format("2006-01-02 15:04:05")
	fmt.Printf("[%v] %v\n", formatted, msg)
}

func cleanIP(ip string) string {
	return strings.Replace(strings.Replace(ip, "]", "", -1), "[", "", -1)
}

// Router returns bytes and content type that should be sent to the client
func Router(path string, res types.Response, srv *Server) ([]byte, string) {
	if v, ok := srv.GetTCPFingerprints().Load(res.IP); ok {
		res.TCPIP = v.(types.TCPIPDetails)
	}
	res.Donate = "Please consider donating to keep this API running. Visit https://tls.peet.ws"
	if res.TLS != nil {
		res.TLS.JA4 = tls.CalculateJa4(res.TLS)
		res.TLS.JA4_r = tls.CalculateJa4_r(res.TLS)
		Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, res.TLS.JA3Hash))
	}
	Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, "-"))

	// if GetUserAgent(res) == "" {
	//	return []byte("{\"error\": \"No user-agent\"}"), "text/html"
	// }
	if srv.GetConfig().LogToDB && res.Path != "/favicon.ico" {
		SaveRequest(res, srv)
	}

	u, err := url.Parse("https://tls.peet.ws" + path)
	var m map[string][]string
	if err != nil || u == nil {
		m = make(map[string][]string)
	} else {
		m, _ = url.ParseQuery(u.RawQuery)
	}

	paths := getAllPaths(srv)
	if u != nil {
		if val, ok := paths[u.Path]; ok {
			return val(res, m)
		}
	}
	// 404
	b, _ := utils.ReadFile("static/404.html")
	return []byte(strings.ReplaceAll(string(b), "/*DATA*/", fmt.Sprintf("%v", GetTotalRequestCount(srv)))), "text/html"
}
