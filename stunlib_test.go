package stunlib // import "github.com/lwahlmeier/stunlib"

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	SPREQ1  = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"
	SPRESP1 = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"
)

func TestTID(t *testing.T) {
	for i := 0; i < 100; i++ {
		X := net.ParseIP("127.0.0.1")
		tid := CreateTID()
		ma := tid.MaskAddress([]byte(X))
		mip := net.IP(ma)
		assert.NotEqual(t, X, mip)
		uma := tid.UnMaskAddress(ma)
		uip := net.IP(uma)
		assert.Equal(t, X, uip)
	}
}

func TestSipMessage(t *testing.T) {
	SP1, err := hex.DecodeString(SPRESP1)
	if err != nil {
		fmt.Println(err)
	}
	sp, err := NewStunPacket(SP1)
	if err != nil {
		fmt.Println(err)
	}
	resp1Addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1").To4(), Port: 32853}

	a, _ := sp.GetAddress()
	assert.Equal(t, SMSuccess, sp.GetStunMessageType())
	assert.True(t, len(sp.GetAllAttributes()) == 4)
	assert.True(t, sp.HasAddress())
	assert.Equal(t, resp1Addr, a)
}

func TestIpv4AddressResp(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest)
	spREQ := spb.Build()
	for i := 0; i < 100; i++ {
		ba := make([]byte, 4)
		rand.Read(ba)
		ipv4 := &net.UDPAddr{IP: net.IP(ba), Port: rand.Intn(65500)}
		spbRESP := spREQ.ToBuilder().SetStunMessage(SMSuccess)
		spbRESP.SetAddress(ipv4)
		spRESP := spbRESP.Build()
		ra, _ := spRESP.GetAddress()
		assert.Equal(t, ipv4, ra)
		spbRESP = spREQ.ToBuilder().SetStunMessage(SMSuccess)
		spbRESP.SetXORAddress(ipv4)
		spRESP = spbRESP.Build()
		ra, _ = spRESP.GetAddress()
		assert.Equal(t, ipv4, ra)
	}
}

func TestIpv6AddressResp(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest)
	spREQ := spb.Build()
	for i := 0; i < 100; i++ {
		ba := make([]byte, 16)
		rand.Read(ba)
		ipv4 := &net.UDPAddr{IP: net.IP(ba), Port: rand.Intn(65500)}
		spbRESP := spREQ.ToBuilder().SetStunMessage(SMSuccess)
		spbRESP.SetAddress(ipv4)
		spRESP := spbRESP.Build()
		ra, _ := spRESP.GetAddress()
		assert.Equal(t, ipv4, ra)
		spbRESP = spREQ.ToBuilder().SetStunMessage(SMSuccess)
		spbRESP.SetXORAddress(ipv4)
		spRESP = spbRESP.Build()
		ra, _ = spRESP.GetAddress()
		assert.Equal(t, ipv4, ra)
	}

}
func TestOffsetAttrib(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest)
	spb.SetAttribue(SASoftware, []byte("TEST!"))
	spREQ := spb.Build()
	ba := spREQ.GetAttribute(SASoftware)
	assert.Equal(t, "TEST!", string(ba))
}

func TestOffsetAttribWithPaddingByte(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest)
	spb.SetPaddingByte(0x20)
	spb.SetAttribue(SASoftware, []byte("TEST!"))
	spREQ := spb.Build()
	ba := spREQ.GetAttribute(SASoftware)
	assert.Equal(t, "TEST!", string(ba))
}
