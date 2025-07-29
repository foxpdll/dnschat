package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/miekg/dns"
)

var (
	server = flag.Bool("server", false, "run as server")
	domain = flag.String("domain", "tst.tst.", "domain name default: tst.tst.")
	msg    = flag.String("msg", "", "Message to send")
	addr   = flag.String("addr", "", "User address like pubkey.domain")
)

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func gzipSt(st string) string {
	var b bytes.Buffer
	gzWriter := gzip.NewWriter(&b)
	_, err := gzWriter.Write([]byte(st))
	if err != nil {
		panic(err)
	}
	err = gzWriter.Close()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b.Bytes())

}

func getMessageByPublicKeyAndTime(publickey, ltime string) (string, string) {
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	row := db.QueryRow("select strftime('%s',dt),text from msg where publickey=? and dt>datetime(?,'unixepoch') order by id limit 1", publickey, ltime)
	dt := ""
	txt := ""
	row.Scan(&dt, &txt)
	checkErr(err)
	db.Close()
	if err == nil {
		return dt, txt
	}
	return "", ""
}

func getMessageMaxTimeByPublicKey(publickey string) uint32 {
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	row := db.QueryRow("select strftime('%s',max(dt)) from msg where publickey=?;", publickey)
	//row := db.QueryRow("select '%s' from msg where publickey=? order by 1 limit 1;", publickey)
	mdt := ""
	row.Scan(&mdt)
	checkErr(err)
	db.Close()
	rr, err := strconv.Atoi(mdt)
	if err == nil {
		return uint32(rr)
	}
	return 0
}

func saveMessageForPublicKey(publickey, text string) {
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	_, err = db.Exec("insert into msg(publickey,text) values(?,?) ", publickey, text)
	checkErr(err)
	db.Close()
}

func getMyPrivateKey() *rsa.PrivateKey {
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	row := db.QueryRow("select privatekey from mykey")
	pkfrombd := ""
	row.Scan(&pkfrombd)
	if pkfrombd == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 128)
		checkErr(err)
		privkey_bytes := x509.MarshalPKCS1PrivateKey(privateKey)
		_, err = db.Exec("insert into mykey(privatekey) values(?)", hex.EncodeToString(privkey_bytes))
		checkErr(err)
		db.Close()
		return privateKey
	}
	db.Close()
	privkey_bytes, err := hex.DecodeString(pkfrombd)
	checkErr(err)
	privateKey, err := x509.ParsePKCS1PrivateKey(privkey_bytes)
	checkErr(err)
	return privateKey
}

func getMyPublicKey() string {
	privateKey := getMyPrivateKey()
	//	hasher := md5.New()
	//	hasher.Write(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey))
	//	md5Hash := hasher.Sum(nil)
	//	hexHash := hex.EncodeToString(md5Hash)
	return hex.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey))
}

func decodeByMyKey(text []byte) []byte {
	privateKey := getMyPrivateKey()
	decoded, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, text)
	checkErr(err)
	return decoded

}

func encodeByMyKey(text []byte) []byte {
	privateKey := getMyPrivateKey()
	encoded, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, text)
	checkErr(err)
	return encoded
}

func getA(name string, addr string, port string) net.IP {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		config = new(dns.ClientConfig)
		config.Servers = append(config.Servers, addr)
		config.Port = port
	}
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return nil
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil
	}
	for _, answer := range r.Answer {
		if a, ok := answer.(*dns.A); ok {
			return a.A
		}
	}
	return nil
}

func getT(name string, addr string, port string) []string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		config = new(dns.ClientConfig)
		config.Servers = append(config.Servers, addr)
		config.Port = port
	}
	c := new(dns.Client)
	c.UDPSize = 65000
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	var ret []string
	if err != nil {
		fmt.Println(err)
		return ret
	}
	if r.Rcode != dns.RcodeSuccess {
		return ret
	}
	for _, answer := range r.Answer {
		if a, ok := answer.(*dns.TXT); ok {
			ret = append(ret, a.Txt[0])
			//return a.Txt[0]
		}
	}
	return ret
}

func serve() {
	server := &dns.Server{Addr: "0.0.0.0:53", Net: "udp", ReusePort: true}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the server: %s\n", err.Error())

	}
}

func getTimeofLastRecvMessage() uint32 {
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	row := db.QueryRow("select max(dt) from mymsg where direction='r';")
	mdt := ""
	row.Scan(&mdt)
	checkErr(err)
	db.Close()
	rr, err := strconv.Atoi(mdt)
	if err == nil {
		return uint32(rr)
	}
	return 0
}

func getTimeOfLastMessageForMe() uint32 {
	myprivkey := getMyPrivateKey()
	mypubkey := hex.EncodeToString(x509.MarshalPKCS1PublicKey(&myprivkey.PublicKey))
	a := getA(mypubkey+"."+*domain, "127.0.0.1", "53")
	if a != nil {
		return ip2int(a)
	}
	return 0
}

func receiveMyMessage() []string {
	publickey := getMyPublicKey()
	lmt := getTimeOfLastMessageForMe()
	lmtl := getTimeofLastRecvMessage()
	lmt = min(lmt, lmtl)
	t := getT(strconv.Itoa(int(lmt))+"."+publickey+"."+*domain, "127.0.0.1", "53")
	if len(t) == 2 && t[0] != "" && t[1] != "" {
		db, err := sql.Open("sqlite", "dnschat.db")
		checkErr(err)
		_, err = db.Exec("insert into mymsg(dt,publickey,text,direction) values(?,?,?,?) ", t[0], publickey, t[1], "r")
		checkErr(err)
		db.Close()
	}
	return t
}

func sendMessage(rec_address, text string) uint32 {
	if rec_address[len(rec_address)-1] != "."[0] {
		rec_address = rec_address + "."
	}
	rec_publickey := strings.Split(rec_address, ".")[0]
	fmt.Println(len(text + "." + rec_address))
	if len(text+"."+rec_address) > 125 {
		fmt.Println("Too big message! Not more 125")
	} else {
		a := getA(text+"."+rec_address, "127.0.0.1", "53")
		if a != nil {
			db, err := sql.Open("sqlite", "dnschat.db")
			checkErr(err)
			_, err = db.Exec("insert into mymsg(dt,publickey,text,direction) values(?,?,?,?) ", ip2int(a), rec_publickey, text, "s")
			checkErr(err)
			db.Close()
			return ip2int(a)
		}
		return 0
	}
	return 0
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	//	fmt.Println(r.Question)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true
	pubkey := strings.Split(r.Question[0].Name, "."+*domain)

	switch r.Question[0].Qtype {
	case dns.TypeA:
		pubkey = strings.Split(pubkey[0], ".")
		if len(pubkey) == 1 {
			mt := getMessageMaxTimeByPublicKey(pubkey[0])
			ret := &dns.A{
				Hdr: dns.RR_Header{Name: *domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   int2ip(uint32(mt)),
			}
			m.Answer = append(m.Answer, ret)
		} else if len(pubkey) == 2 {
			saveMessageForPublicKey(pubkey[1], pubkey[0])
			mt := getMessageMaxTimeByPublicKey(pubkey[1])
			ret := &dns.A{
				Hdr: dns.RR_Header{Name: *domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   int2ip(uint32(mt)),
			}
			m.Answer = append(m.Answer, ret)
		}
	case dns.TypeTXT:
		pubkey = strings.Split(pubkey[0], ".")
		if len(pubkey) == 2 {
			//saveMessageForPublicKey(pubkey[1], pubkey[0])
			lmt, lm := getMessageByPublicKeyAndTime(pubkey[1], pubkey[0])
			t1 := &dns.TXT{
				Hdr: dns.RR_Header{Name: *domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{lmt},
			}
			t2 := &dns.TXT{
				Hdr: dns.RR_Header{Name: *domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{lm},
			}
			m.Answer = append(m.Answer, t1, t2)

		}

	}

	w.WriteMsg(m)

}

func RunLocalUDPServer() {
	dns.HandleFunc(*domain, handleReflect)
	fmt.Println("Starting UDP server for domain:" + *domain)
	go serve()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}

func main() {
	os.Setenv("GODEBUG", "rsa1024min=0")
	db, err := sql.Open("sqlite", "dnschat.db")
	checkErr(err)
	_, err = db.Exec(`create table if not exists mykey (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, privatekey text)`)
	checkErr(err)
	_, err = db.Exec(`create table if not exists msg (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, dt TEXT NOT NULL DEFAULT current_timestamp, publickey text, text text)`)
	checkErr(err)
	_, err = db.Exec(`create table if not exists mymsg (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, dt TEXT NOT NULL DEFAULT current_timestamp, direction text, publickey text, text text)`)
	checkErr(err)
	db.Close()

	//fmt.Println(int2ip(1753114595))
	//	ip, _, err := net.ParseCIDR(a)
	//	fmt.Println(string(decodeByMyKey(encodeByMyKey([]byte("foxpdll")))))

	flag.Parse()
	if *server {
		fmt.Println("I use domain:", *domain)
		fmt.Println("My public key is:", getMyPublicKey())
		fmt.Println("My address is:", getMyPublicKey()+"."+*domain)
		RunLocalUDPServer()
	} else {
		if *addr != "" && *msg != "" {
			sendMessage(*addr, string(encodeByMyKey([]byte(*msg))))
		} else {
			fmt.Println("I use domain:", *domain)
			fmt.Println("My public key is:", getMyPublicKey())
			fmt.Println("My address is:", getMyPublicKey()+"."+*domain)
			fmt.Println("Recieving messages:")
			for true {
				res := receiveMyMessage()
				if len(res) == 2 && res[0] != "" && res[1] != "" {
					fmt.Println("Recieved:", res)
				} else {
					time.Sleep(5 * time.Second)
				}
			}
		}
	}

	//	mypubkey := getMyPublicKey()
	//fmt.Println(myhash)
	//fmt.Println(len(myhash))
	//fmt.Println(x509.MarshalPKCS1PublicKey(&myprivkey.PublicKey))
	//fmt.Println(len(x509.MarshalPKCS1PublicKey(&myprivkey.PublicKey)))

	//	lmt := getTimeOfLastMessageForMe()
	//	fmt.Println(lmt)

	//	lmt = getTimeOfLastMessageForMe()
	//	fmt.Println(lmt)

}
