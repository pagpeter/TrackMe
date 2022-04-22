package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

type RequestLog struct {
	UserAgent string `bson:"user_agent"`
	Ja3       string `bson:"ja3"`
	H2        string `bson:"h2"`
	Lastseen  int64  `bson:"lastseen"`
	Timesseen int    `bson:"timesseen"`
	Hash      string `bson:"hash"`
}

func SaveRequest(req Response) {
	reqLog := RequestLog{
		Ja3: req.TLS.JA3}

	var headers []string
	if req.HTTPVersion == "h2" {
		headers = req.Http2.SendFrames[len(req.Http2.SendFrames)-1].Headers
		reqLog.H2 = req.Http2.AkamaiFingerprint
	} else if req.HTTPVersion == "http/1.1" {
		headers = req.Http1.Headers
		reqLog.H2 = "-"
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent: ") {
			reqLog.UserAgent = strings.Split(header, ": ")[1]
		}
	}

	reqLog.Hash = GetMD5Hash(reqLog.UserAgent + reqLog.H2 + reqLog.Ja3)

	filter := bson.M{
		"hash": reqLog.Hash,
	}

	// Check if hash already exists
	var result RequestLog
	if err := collection.FindOne(context.TODO(), filter).Decode(&result); err != nil {
		log.Println(err)
	}

	if result.Hash != "" {
		fmt.Println("updating...")
		_, err := collection.UpdateOne(context.TODO(), filter, bson.D{{"$inc", bson.D{{"timesseen", 1}}}})
		if err != nil {
			log.Println(err)
		}
	} else {

		reqLog.Lastseen = time.Now().Unix()
		reqLog.Timesseen = 1

		id, err := collection.InsertOne(ctx, reqLog)
		if err != nil {
			log.Println(err)

		}
		log.Println("Logged req", id)
	}
}
