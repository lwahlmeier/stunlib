package main // import "github.com/lwahlmeier/stunlib"

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/lwahlmeier/stunlib"
)

const processors = 1
const queueSize = 1

func main() {
	addr, err := net.ResolveUDPAddr("udp", os.Args[1])
	checkError(err)
	conn, err := net.ListenUDP("udp", addr)
	checkError(err)
  //We send the reads to a channel to be processed by another goRoutine.
	//This you can adjust this for better performance
  //This is really only needed for doing things like finger printing
  //Of throttling of IPs
	writer := make(chan func(), 1)
	for i := 0; i < 1; i++ {
		go func() {
			for {
				f := <-writer
				f()
			}
		}()
	}
	//Use main to sit on conn.Read
	UDPRead(conn, writer)
}

func UDPRead(conn *net.UDPConn, writer chan func()) {
	count := 0
	start := time.Now()
	for {
		ba := make([]byte, 1500)
		n, sa, err := conn.ReadFromUDP(ba)
		checkError(err)
		sp, err := stunlib.NewStunPacket(ba[:n])
		checkError(err)
		writer <- func() {
			SendResp(conn, sa, sp)
		}
		count++
		fmt.Println("-----------------------------")
		fmt.Printf("%s=>%s'\n", conn.LocalAddr(), sa)
		fmt.Printf("%d:%s\n", count, time.Since(start))
		fmt.Printf("%f\n", (time.Since(start).Seconds()*(1000))/float64(count))
		fmt.Printf("GoRoutines:%d\n", runtime.NumGoroutine())
	}
}

func SendResp(conn *net.UDPConn, uaddr *net.UDPAddr, sp *stunlib.StunPacket) {
	spb := sp.ToBuilder()
	spb.ClearAttribues()
	spb.SetXORAddress(uaddr)
	conn.WriteToUDP(spb.Build().GetBytes(), uaddr)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("ERR")
		fmt.Println(err)
		os.Exit(1)
	}
}
