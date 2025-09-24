package server

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
	"go.mongodb.org/mongo-driver/bson"
)

type RequestLog struct {
	UserAgent string `bson:"user_agent"`
	JA3       string `bson:"ja3"`
	H2        string `bson:"h2"`
	PeetPrint string `bson:"peetprint"`
	IP        string `bson:"ip"`
	Time      int64
}

type ByJA3 struct {
	JA3        string         `json:"ja3"`
	H2         map[string]int `json:"h2_fps"`
	PeetPrint  map[string]int `json:"peet_prints"`
	UserAgents map[string]int `json:"user_agents"`
}

type ByPeetPrint struct {
	PeetPrint  string         `json:"peet_print"`
	JA3        map[string]int `json:"ja3s"`
	H2         map[string]int `json:"h2_fps"`
	UserAgents map[string]int `json:"user_agents"`
}

type ByH2 struct {
	H2         string         `json:"h2_fp"`
	JA3        map[string]int `json:"ja3s"`
	PeetPrint  map[string]int `json:"peet_prints"`
	UserAgents map[string]int `json:"user_agents"`
}

type ByUserAgent struct {
	UserAgent string         `json:"useragent"`
	H2        map[string]int `json:"h2_fps"`
	JA3       map[string]int `json:"ja3s"`
	PeetPrint map[string]int `json:"peet_prints"`
}

func SaveRequest(req types.Response, srv *Server) {
	reqLog := RequestLog{
		JA3:       req.TLS.JA3,
		PeetPrint: req.TLS.PeetPrint,
		Time:      time.Now().Unix(),
	}

	if req.HTTPVersion == "h2" {
		reqLog.H2 = req.Http2.AkamaiFingerprint
	} else if req.HTTPVersion == "http/1.1" {
		reqLog.H2 = "-"
	}
	if srv.GetConfig().LogIPs {
		parts := strings.Split(req.IP, ":")
		ip := strings.Join(parts[0:len(parts)-1], ":")
		reqLog.IP = ip
	}
	reqLog.UserAgent = GetUserAgent(req)

	if srv.IsConnectedToDB() && srv.State.Config.LogToDB {
		_, err := srv.GetMongoCollection().InsertOne(srv.GetMongoContext(), reqLog)
		if err != nil {
			log.Println(err)
		}
	}
}

func GetTotalRequestCount(srv *Server) int64 {
	if !srv.IsConnectedToDB() {
		return 999
	}
	itemCount, err := srv.GetMongoCollection().CountDocuments(srv.GetMongoContext(), bson.M{})
	if err != nil {
		log.Println(err)
		return -1
	}
	return itemCount
}

func queryDB(query, val string, srv *Server) []RequestLog {
	dbRes := []RequestLog{}
	cur, err := srv.GetMongoCollection().Find(srv.GetMongoContext(), bson.D{{Key: query, Value: val}})
	if err != nil {
		log.Println("Error quering data:", err)
		return dbRes
	}

	for cur.Next(srv.GetMongoContext()) {
		var b RequestLog
		err := cur.Decode(&b)
		if err != nil {
			log.Println("Error decoding:", err)
			return dbRes
		}
		dbRes = append(dbRes, b)
	}

	if err := cur.Err(); err != nil {
		log.Println("Error - cur.Err()", err)
		return dbRes
	}

	if cur.Close(srv.GetMongoContext()) != nil {
		log.Println("Could not close")
	}
	return dbRes
}

const COUNT = 10

func GetByJa3(val string, srv *Server) ByJA3 {
	res := ByJA3{
		JA3:        val,
		H2:         map[string]int{},
		PeetPrint:  map[string]int{},
		UserAgents: map[string]int{},
	}

	dbRes := queryDB("ja3", val, srv)

	for _, r := range dbRes {
		if v, ok := res.H2[r.H2]; ok {
			res.H2[r.H2] = v + 1
		} else {
			res.H2[r.H2] = 1
		}

		if v, ok := res.PeetPrint[r.PeetPrint]; ok {
			res.PeetPrint[r.PeetPrint] = v + 1
		} else {
			res.PeetPrint[r.PeetPrint] = 1
		}

		if v, ok := res.UserAgents[r.UserAgent]; ok {
			res.UserAgents[r.UserAgent] = v + 1
		} else {
			res.UserAgents[r.UserAgent] = 1
		}
	}

	res.PeetPrint = utils.SortByVal(res.PeetPrint, COUNT)
	res.H2 = utils.SortByVal(res.H2, COUNT)
	res.UserAgents = utils.SortByVal(res.UserAgents, COUNT)

	return res
}

func GetByH2(val string, srv *Server) ByH2 {
	res := ByH2{
		H2:         val,
		JA3:        map[string]int{},
		PeetPrint:  map[string]int{},
		UserAgents: map[string]int{},
	}

	dbRes := queryDB("h2", val, srv)

	for _, r := range dbRes {
		if v, ok := res.JA3[r.JA3]; ok {
			res.JA3[r.JA3] = v + 1
		} else {
			res.JA3[r.JA3] = 1
		}

		if v, ok := res.PeetPrint[r.PeetPrint]; ok {
			res.PeetPrint[r.PeetPrint] = v + 1
		} else {
			res.PeetPrint[r.PeetPrint] = 1
		}

		if v, ok := res.UserAgents[r.UserAgent]; ok {
			res.UserAgents[r.UserAgent] = v + 1
		} else {
			res.UserAgents[r.UserAgent] = 1
		}
	}

	res.PeetPrint = utils.SortByVal(res.PeetPrint, COUNT)
	res.JA3 = utils.SortByVal(res.JA3, COUNT)
	res.UserAgents = utils.SortByVal(res.UserAgents, COUNT)
	return res
}

func GetByPeetPrint(val string, srv *Server) ByPeetPrint {
	res := ByPeetPrint{
		PeetPrint:  val,
		H2:         map[string]int{},
		JA3:        map[string]int{},
		UserAgents: map[string]int{},
	}

	dbRes := queryDB("peetprint", val, srv)

	for _, r := range dbRes {
		if v, ok := res.H2[r.H2]; ok {
			res.H2[r.H2] = v + 1
		} else {
			res.H2[r.H2] = 1
		}

		if v, ok := res.JA3[r.JA3]; ok {
			res.JA3[r.JA3] = v + 1
		} else {
			res.JA3[r.JA3] = 1
		}

		if v, ok := res.UserAgents[r.UserAgent]; ok {
			res.UserAgents[r.UserAgent] = v + 1
		} else {
			res.UserAgents[r.UserAgent] = 1
		}
	}
	res.JA3 = utils.SortByVal(res.JA3, COUNT)
	res.H2 = utils.SortByVal(res.H2, COUNT)
	res.UserAgents = utils.SortByVal(res.UserAgents, COUNT)

	return res
}

func GetByUserAgent(val string, srv *Server) ByUserAgent {
	res := ByUserAgent{
		UserAgent: val,
		H2:        map[string]int{},
		JA3:       map[string]int{},
		PeetPrint: map[string]int{},
	}

	decodedValue, err := url.QueryUnescape(val)
	if err != nil {
		return res
	}
	fmt.Println(val)

	dbRes := queryDB("user_agent", decodedValue, srv)

	for _, r := range dbRes {
		if v, ok := res.H2[r.H2]; ok {
			res.H2[r.H2] = v + 1
		} else {
			res.H2[r.H2] = 1
		}

		if v, ok := res.JA3[r.JA3]; ok {
			res.JA3[r.JA3] = v + 1
		} else {
			res.JA3[r.JA3] = 1
		}

		if v, ok := res.PeetPrint[r.PeetPrint]; ok {
			res.PeetPrint[r.PeetPrint] = v + 1
		} else {
			res.PeetPrint[r.PeetPrint] = 1
		}
	}
	res.JA3 = utils.SortByVal(res.JA3, COUNT)
	res.H2 = utils.SortByVal(res.H2, COUNT)
	res.PeetPrint = utils.SortByVal(res.PeetPrint, COUNT)

	return res
}
