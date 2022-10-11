package main

import (
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

type RequestLog struct {
	UserAgent string `bson:"user_agent"`
	Ja3       string `bson:"ja3"`
	H2        string `bson:"h2"`
	PeetPrint string `bson:"peetprint"`
	IP        string `bson:"ip"`
	Time      int64
}

func SaveRequest(req Response) {
	reqLog := RequestLog{
		Ja3:       req.TLS.JA3,
		PeetPrint: req.TLS.PeetPrint,
		Time:      time.Now().Unix(),
	}

	if req.HTTPVersion == "h2" {
		reqLog.H2 = req.Http2.AkamaiFingerprint
	} else if req.HTTPVersion == "http/1.1" {
		reqLog.H2 = "-"
	}
	if c.LogIPs {
		parts := strings.Split(req.IP, ":")
		ip := strings.Join(parts[0:len(parts)-1], ":")
		reqLog.IP = ip
	}
	reqLog.UserAgent = GetUserAgent(req)

	_, err := collection.InsertOne(ctx, reqLog)
	if err != nil {
		log.Println(err)
	}
}

func GetTotalRequestCount() int64 {
	itemCount, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Println(err)
		return -1
	}
	return itemCount
}
