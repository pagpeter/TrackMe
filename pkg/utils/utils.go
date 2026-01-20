package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

var dataFrameFlags = map[http2.Flags]string{
	http2.FlagDataEndStream: "EndStream (0x1)",
	http2.FlagDataPadded:    "Padded (0x8)",
}

var pushFrameFlags = map[http2.Flags]string{
	http2.FlagPushPromiseEndHeaders: "EndHeaders (0x4)",
	http2.FlagPushPromisePadded:     "Padded (0x8)",
}

var headersFrameFlags = map[http2.Flags]string{
	http2.FlagHeadersEndStream:  "EndStream (0x1)",
	http2.FlagHeadersEndHeaders: "EndHeaders (0x4)",
	http2.FlagHeadersPadded:     "Padded (0x8)",
	http2.FlagHeadersPriority:   "Priority (0x20)",
}

func GetAllFlags(frame http2.Frame) []string {
	var flagsArray []string
	flags := frame.Header().Flags

	switch frame.(type) {
	case *http2.SettingsFrame:
		if flags.Has(http2.FlagSettingsAck) {
			flagsArray = append(flagsArray, "Ack (0x1)")
		}
	case *http2.HeadersFrame:
		for _, key := range getKeysInOrder(headersFrameFlags) {
			if flags.Has(key) {
				flagsArray = append(flagsArray, headersFrameFlags[key])
			}
		}
	case *http2.DataFrame:
		for _, key := range getKeysInOrder(dataFrameFlags) {
			if flags.Has(key) {
				flagsArray = append(flagsArray, dataFrameFlags[key])
			}
		}
	case *http2.PingFrame:
		if flags.Has(http2.FlagPingAck) {
			flagsArray = append(flagsArray, "Ack (0x1)")
		}
	case *http2.ContinuationFrame:
		if flags.Has(http2.FlagContinuationEndHeaders) {
			flagsArray = append(flagsArray, "EndHeaders (0x4)")
		}
	case *http2.PushPromiseFrame:
		for _, key := range getKeysInOrder(pushFrameFlags) {
			if flags.Has(key) {
				flagsArray = append(flagsArray, pushFrameFlags[key])
			}
		}
	}

	return flagsArray
}


func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func ReadFile(filename string) ([]byte, error) {
	body, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read file %s: %w", filename, err)
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

func GetAdmin() (string, bool) {
	// This function will be updated to use the server config
	// For now, returning empty values to avoid compilation errors
	return "", false
}

func IsIPBlocked(ip string) bool {
	rawIPs, err := ReadFile("blockedIPs")
	if err != nil {
		WriteToFile("blockedIPs", []byte(""))
		return false
	}
	ips := strings.Split(string(rawIPs), "\n")

	for _, i := range ips {
		if ip == i {
			return true
		}
	}
	return false
}

func getKeysInOrder(m map[http2.Flags]string) []http2.Flags {
	keys := make([]http2.Flags, 0)
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	return keys
}

func SplitBytesIntoChunks(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

type kv struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

func SortByVal(m map[string]int, x int) map[string]int {
	// Turning the map into this structure

	var ss []kv
	for k, v := range m {
		ss = append(ss, kv{k, v})
	}

	// Then sorting the slice by value, higher first.
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	res := map[string]int{}
	var tmp []kv
	if len(ss) > x {
		tmp = ss[:x]
	} else {
		tmp = ss
	}
	for _, obj := range tmp {
		res[obj.Key] = obj.Value
	}
	return res
}

func GetParam(_ string, m url.Values) string {
	if val, ok := m["by"]; ok {
		if len(val) != 0 {
			return val[0]
		}
	}
	return ""
}

func SHA256trunc(in string) string {
	h := sha256.New()
	h.Write([]byte(in))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func ToHexAll(in []string, filterOut bool, shouldSort bool) []string {

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
