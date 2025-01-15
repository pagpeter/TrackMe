package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"main/database"
	"net/url"
	"strings"
	"time"
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
func Router(path string, res Response) ([]byte, string) {
	if v, ok := TCPFingerprints.Load(cleanIP(res.IP)); ok {
		res.TCPIP = v.(TCPIPDetails)
	}
	res.TLS.JA4 = CalculateJa4(res.TLS)
	res.Donate = "Please consider donating to keep this API running. Visit https://tls.peet.ws"
	Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.path, res.TLS.JA3Hash))
	// if GetUserAgent(res) == "" {
	//	return []byte("{\"error\": \"No user-agent\"}"), "text/html"
	// }
	if LoadedConfig.LogToDB && res.path != "/favicon.ico" {
		// SaveRequest(res)
	}

	parts := strings.Split(res.IP, ":")
	ip := strings.Join(parts[0:len(parts)-1], ":")

	h2i := "-"
	if res.HTTPVersion == "h2" {
		h2i = res.Http2.AkamaiFingerprint
	}

	err := queries.InsertRequestLog(context.Background(), database.InsertRequestLogParams{
		CreatedAt: time.Now(),
		UserAgent: sql.NullString{
			String: GetUserAgent(res),
			Valid:  GetUserAgent(res) != "",
		},
		Ja3: sql.NullString{
			String: res.TLS.JA3,
			Valid:  res.TLS.JA3 != "",
		},
		H2: sql.NullString{
			String: h2i,
			Valid:  h2i != "",
		},
		PeetPrint: sql.NullString{
			String: res.TLS.PeetPrint,
			Valid:  res.TLS.PeetPrint != "",
		},
		IpAddress: sql.NullString{
			String: ip,
			Valid:  ip != "",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	u, _ := url.Parse("https://localhost" + path)
	m, _ := url.ParseQuery(u.RawQuery)

	paths := getAllPaths()
	if val, ok := paths[u.Path]; ok {
		return val(res, m)
	}
	// 404
	b, _ := ReadFile("static/404.html")
	// return []byte(strings.ReplaceAll(string(b), "/*DATA*/", fmt.Sprintf("%v", GetTotalRequestCount()))), "text/html"
	return []byte(strings.ReplaceAll(string(b), "/*DATA*/", "TODO")), "text/html" //TODO
}
