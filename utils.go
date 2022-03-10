package main

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
)

var GREASE = []string{
	"0x0A0A",
	"0x0A0A",
	"0x1A1A",
	"0x2A2A",
	"0x3A3A",
	"0x4A4A",
	"0x5A5A",
	"0x6A6A",
	"0x7A7A",
	"0x8A8A",
	"0x9A9A",
	"0xAAAA",
	"0xBABA",
	"0xCACA",
	"0xDADA",
	"0xEAEA",
	"0xFAFA",
	"0xA0A",
}

func isGrease(cipher string) bool {
	for _, g := range GREASE {
		if g == cipher {
			return true
		}
	}
	return false
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