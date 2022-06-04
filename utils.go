package main

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func GetUserAgent(res Response) string {
	var headers []string
	var ua string

	if res.HTTPVersion == "h2" {
		headers = res.Http2.SendFrames[len(res.Http2.SendFrames)-1].Headers
	} else if res.HTTPVersion = "http/1.1" {
		if res.Http1 == nil {
			return ""
		}
		headers = res.Http1.Headers
	} else {
		return ""
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent: ") {
			ua = strings.Split(header, ": ")[1]
		}
	}

	return ua
}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func ReadFile(filename string) ([]byte, error) {
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println("unable to read file: %v", err)
		return nil, err
	}
	return body, nil
}

func WriteToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}
