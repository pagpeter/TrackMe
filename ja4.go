package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func sha256trunc(in string) string {
	h := sha256.New()
	h.Write([]byte(in))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func toHexAll(in []string, filterOut bool, shouldSort bool) []string {

	nums := []int{}
	for _, v := range in {
		num, _ := strconv.Atoi(v)
		nums = append(nums, num)
	}

	if shouldSort {
		sort.Ints(nums)
	}

	out := []string{}

	for _, num := range nums {
		str := fmt.Sprintf("%04x", num)
		if filterOut && str == "0000" {
			continue
		}
		if filterOut && str == "0010" {
			continue
		}
		out = append(out, str)
	}

	return out
}

func ja4a(tls TLSDetails) string {
	proto := "t" // we dont support quic (q), only tcp (t)

	tlsVersionMapping := map[string]string{
		"769": "10", // TLS 1.0
		"770": "11", // TLS 1.1
		"771": "12", // TLS 1.2
		"772": "13", // TLS 1.3
	}

	httpVersionMapping := map[string]string{
		"2":   "h2", // HTTP/2
		"1.1": "h1", // HTTP/1
		"1.0": "h1", // HTTP/1
		"0.9": "h1", // HTTP/1
	}

	tlsVersion := getOrReturnOG(tls.NegotiatedVesion, tlsVersionMapping)

	sniMode := "d" // IP: i, domain: d
	numSuites := len(strings.Split(strings.Split(tls.JA3, ",")[1], "-"))
	numExtensions := len(strings.Split(strings.Split(tls.JA3, ",")[2], "-"))
	firstALPN := getOrReturnOG(strings.Split(strings.Split(tls.PeetPrint, "|")[1], "-")[0], httpVersionMapping)

	return fmt.Sprintf("%v%v%v%v%v%v", proto, tlsVersion, sniMode, numSuites, numExtensions, firstALPN)
}

func ja4b_r(tls TLSDetails) string {
	suites := strings.Split(strings.Split(tls.JA3, ",")[1], "-")
	parsed := toHexAll(suites, false, true)
	// fmt.Println("ja4b:", strings.Join(parsed, ","))
	return strings.Join(parsed, ",")
}

func ja4b(tls TLSDetails) string {
	result := ja4b_r(tls)
	return sha256trunc(result)
}

func ja4c_r(tls TLSDetails) string {
	// Get extensions and signature algorithms
	extensions := strings.Split(strings.Split(tls.JA3, ",")[2], "-")
	sigAlgs := strings.Split(strings.Split(tls.PeetPrint, "|")[3], "-")

	// Convert extensions to hex, filter GREASE and padding, and sort
	parsedExt := []string{}
	for _, ext := range extensions {
		num, _ := strconv.Atoi(ext)
		hexStr := fmt.Sprintf("%04x", num)
		// Skip if it's a GREASE value or padding extension
		if isGrease("0x"+strings.ToUpper(hexStr)) || hexStr == "0010" {
			continue
		}
		parsedExt = append(parsedExt, hexStr)
	}
	sort.Strings(parsedExt)

	// Convert signature algorithms to hex
	parsedAlg := []string{}
	for _, alg := range sigAlgs {
		if alg == "GREASE" {
			continue
		}
		num, _ := strconv.Atoi(alg)
		hexStr := fmt.Sprintf("%04x", num)
		parsedAlg = append(parsedAlg, hexStr)
	}

	// Join the results
	parsed := strings.Join(parsedExt, ",") + "_" + strings.Join(parsedAlg, ",")
	return parsed
}

func ja4c(tls TLSDetails) string {
	result := ja4c_r(tls)
	return sha256trunc(result)
}

func CalculateJa4(tls TLSDetails) string {
	return ja4a(tls) + "_" + ja4b(tls) + "_" + ja4c(tls)
}

func CalculateJa4_r(tls TLSDetails) string {
	return ja4a(tls) + "_" + ja4b_r(tls) + "_" + ja4c_r(tls)
}
