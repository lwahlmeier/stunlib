package main // import "github.com/lwahlmeier/stunlib"

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lwahlmeier/stunlib"
)

const loops = 1
const msDelay = 500

func main() {
	fmt.Println(os.Args)
	_, err := net.ResolveUDPAddr("udp", os.Args[1])
	checkError(err)
	addr, err := net.ResolveUDPAddr("udp", os.Args[2])
	checkError(err)
	conn, err := net.ListenUDP("udp", addr)
	checkError(err)

	for i := 0; i < loops; i++ {
		go SendPing(conn)
	}
	UDPRead(conn)
}
func UDPRead(conn *net.UDPConn) {
	count := 0
	start := time.Now()
	for {
		ba := make([]byte, 1024)
		n, sa, err := conn.ReadFromUDP(ba)
		checkError(err)
		sp2, err := stunlib.NewStunPacket(ba[:n])
		checkError(err)
		fmt.Println("-----")
		ma, err := sp2.GetAddress()
		checkError(err)
		count++
		for _, v := range sp2.GetAllAttributes() {
			fmt.Printf("%X\n", v)
		}
		fmt.Printf("%s\n", sp2.GetTxID().String())
		fmt.Printf("%X\n", sp2.GetStunMessageType())
		fmt.Printf("%s=>%s=>%s'\n", conn.LocalAddr(), sa, ma)
		fmt.Printf("%d:%s\n", count, time.Since(start))
		fmt.Printf("%f\n", (time.Since(start).Seconds()*(1000))/float64(count))
	}
}

func SendPing(conn *net.UDPConn) {
	for {
		spb := stunlib.NewStunPacketBuilder()

		spb.SetStunMessage(stunlib.SMRequest)
		// hosts, err := net.LookupHost(os.Args[1])
		// checkError(err)
		// rv := rand.Intn(len(hosts))
		// host := hosts[rv]
		sp := spb.Build()
		ss, err := net.ResolveUDPAddr("udp4", os.Args[1])
		checkError(err)
		_, err = conn.WriteToUDP(sp.GetBytes(), ss)
		checkError(err)
		time.Sleep(time.Millisecond * msDelay)
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println("ERR")
		fmt.Println(err)
		os.Exit(1)
	}
}
