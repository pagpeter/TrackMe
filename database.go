package main

import (
	"fmt"

	c "github.com/ostafen/clover"
)

func SaveRequest(req Response) {
	doc := c.NewDocument()

	var headers []string
	if req.HTTPVersion == "h2" {
		headers = req.Http2.SendFrames[len(req.Http2.SendFrames)-1].Headers
	} else if req.HTTPVersion == "http/1.1" {
		headers = req.Http1.Headers
	}

	doc.Set("ja3", req.TLS.JA3)
	if req.Http2 != nil {
		doc.Set("akamai", req.Http2.AkamaiFingerprint)
	}
	doc.Set("headers", headers)

	_, err := db.InsertOne("requests", doc)
	if err != nil {
		fmt.Println("Error saving request", err)
	}
}
