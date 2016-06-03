package main

import (
	"fmt"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	bw2 "gopkg.in/immesys/bw2bind.v5"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const BUFSIZE = 4096
const IP6PREFIX = "fc00:424f:5353:5741:5645::"
const IP6PREFIX_LEN = "/80"
const IP4PREFIX = "10.101.0"
const IP4PREFIX_LEN = "/16"

var ipsuffix = "1"

func runCommand(cmdstring string) {
	log.Println(cmdstring)
	args := strings.Split(cmdstring, " ")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalln(err)
	}
}

func getSrcDst(buffer []byte) (src, dst string) {
	if waterutil.IsIPv6(buffer) {
		hdr, err := ipv6.ParseHeader(buffer)
		if err != nil {
			log.Fatalln(err)
		}
		src = hdr.Src.String()
		dst = hdr.Dst.String()
	} else {
		hdr, err := ipv4.ParseHeader(buffer)
		if err != nil {
			log.Fatalln(err)
		}
		src = hdr.Src.String()
		dst = hdr.Dst.String()
	}
	return
}

type keeper struct {
	sync.RWMutex
	client  *bw2.BW2Client
	tun     *water.Interface
	subs    map[string]chan *bw2.SimpleMessage
	IPtoURI map[string][]string
	// map: ip.src address to outgoing URI
	replies map[string]string
}

func newkeeper(client *bw2.BW2Client, tun *water.Interface) *keeper {
	return &keeper{
		client:  client,
		tun:     tun,
		subs:    make(map[string]chan *bw2.SimpleMessage),
		IPtoURI: make(map[string][]string),
		replies: make(map[string]string),
	}
}

func (k *keeper) newsub(uri string) {
	k.Lock()
	defer k.Unlock()
	if _, found := k.subs[uri]; !found {
		log.Printf("listen on %s\n", uri)
		subscription := k.client.SubscribeOrExit(&bw2.SubscribeParams{
			URI: uri,
		})
		go func() {
			for msg := range subscription {
				replyAddr := msg.GetOnePODF("64.0.1.0")
				if replyAddr == nil {
					log.Println("no reply addr")
					continue
				}
				po := msg.GetOnePODF("1.0.1.1")
				if po == nil {
					log.Printf("NONE\n")
					continue
				}
				src, dst := getSrcDst(po.GetContents())
				k.replies[src] = string(replyAddr.GetContents())
				log.Println("----------")
				log.Printf("RECV ON SUB src: %v, dst: %v", src, dst)
				log.Printf("reply addr: %s\n", string(replyAddr.GetContents()))

				k.tun.Write(po.GetContents())

			}
		}()
		k.subs[uri] = subscription
	}
}

func (k *keeper) GetTopic(addr string) (ret []string) {
	if uris, found := k.IPtoURI[addr]; found {
		ret = uris
		return
	}
	log.Printf("Reverse DNS on %s\n", addr)
	names := []string{"bw2ssltest.cal-sdb.org"}
	//names, err := net.LookupAddr(addr)
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
	for _, name := range names {
		txts, err := net.LookupTXT(name)
		if err != nil {
			log.Println(err)
			return
		}
		if len(txts) > 0 {
			log.Printf("> TXT: %v\n", txts)
			ret = append(ret, txts...)
		}
	}
	k.Lock()
	if _, found := k.IPtoURI[addr]; !found {
		k.IPtoURI[addr] = ret
	}
	k.Unlock()
	return
}

func main() {
	bw := bw2.ConnectOrExit("")
	bw.OverrideAutoChainTo(true)
	bw.SetEntityFile("bw2ssltest.ent")

	var suburi string
	if len(os.Args) > 2 {
		suburi = os.Args[1]
		ipsuffix = os.Args[2]
	} else {
		suburi = "gabe.ns/ip/bw2ssltest"
		ipsuffix = strconv.Itoa(rand.Intn(99))
	}

	iface, err := water.NewTUN("")
	runCommand("/sbin/ip link set dev tun0 up")
	runCommand(fmt.Sprintf("/sbin/ip -6 addr add %s dev tun0", IP6PREFIX+ipsuffix+IP6PREFIX_LEN))
	runCommand(fmt.Sprintf("/sbin/ip addr add %s dev tun0", IP4PREFIX+"."+ipsuffix+IP4PREFIX_LEN))
	keeper := newkeeper(bw, iface)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalln(err)
	}
	keeper.newsub(suburi)
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				log.Println(ipnet.IP.String())
			} else if ipnet.IP.To16() != nil {
				log.Println(ipnet.IP.String())
			}
		}
	}

	buffer := make([]byte, BUFSIZE)
	var size int
	// reading the TUN interface for outgoing packets
	for {
		if size, err = iface.Read(buffer); err != nil {
			log.Fatalln(err)
		}

		src, dst := getSrcDst(buffer)

		po, err := bw2.LoadPayloadObject(bw2.FromDotForm("1.0.1.1"), buffer[:size])
		if err != nil {
			log.Fatalln(err)
		}
		if dst == src {
			continue
		}
		log.Println("----------")
		log.Printf("SENDING msg src %v dst %v", src, dst)
		po2 := bw2.CreateStringPayloadObject(suburi)
		uris := keeper.GetTopic(dst)
		keeper.RLock()
		if replyURI, found := keeper.replies[dst]; found {
			for _, u := range uris {
				if u == replyURI {
					goto done
				}
			}
			uris = append(uris, replyURI)
		}
	done:
		keeper.RUnlock()
		log.Printf("sending to uris %v\n", uris)
		for _, uri := range uris {
			if uri == suburi {
				continue
			}
			log.Printf("PUB on %s: %v %v\n", uri, po2.GetPODotNum(), po2.Value())
			err := bw.Publish(&bw2.PublishParams{
				URI:            uri,
				PayloadObjects: []bw2.PayloadObject{po, po2},
			})
			if err != nil {
				log.Println(err)
			}
		}
	}
}
