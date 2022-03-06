package main

import (
	"fmt"

	c "github.com/ostafen/clover"
)

func SaveRequest(req Response) {
	doc := c.NewDocument()

	headers := req.Http2.SendFrames[len(req.Http2.SendFrames)-1].Headers

	doc.Set("ja3", req.TLS.JA3)
	doc.Set("akamai", req.Http2.AkamaiFingerprint)
	doc.Set("headers", headers)

	res, err := db.InsertOne("requests", doc)
	if err != nil {
		fmt.Println("Error saving request", err)
	}
}
