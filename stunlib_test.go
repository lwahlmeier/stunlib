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
		X := &net.UDPAddr{IP: net.ParseIP("192.0.2.1").To4(), Port: 32853}
		tid := CreateTID()
		ma := tid.MaskAddress(X)
		mip := net.IP(ma)
		assert.NotEqual(t, X, mip)
		uma := tid.UnMaskAddress(ma)
		assert.Equal(t, X, uma)
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
	assert.True(t, sp.HasFingerPrint())
	assert.True(t, VerifyFingerPrint(*sp))
}

func TestSipMessage2(t *testing.T) {
	SP1, err := hex.DecodeString(SPREQ1)
	if err != nil {
		fmt.Println(err)
	}
	sp, err := NewStunPacket(SP1)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, SMRequest, sp.GetStunMessageType())
	assert.True(t, len(sp.GetAllAttributes()) == 6)
	assert.False(t, sp.HasAddress())
	assert.True(t, sp.HasFingerPrint())
	assert.True(t, VerifyFingerPrint(*sp))
	// assert.Equal(t, resp1Addr, a)
}

func TestCreateFingerPrint(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest).AddFingerprint(true)
	sp := spb.Build()
	assert.True(t, sp.HasFingerPrint())
	assert.True(t, VerifyFingerPrint(*sp))
}

func TestBadFingerPrint1(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest)
	sp := spb.Build()

	assert.False(t, sp.HasFingerPrint())
	assert.False(t, VerifyFingerPrint(*sp))
}

func TestBadFingerPrint2(t *testing.T) {
	spb := NewStunPacketBuilder()
	spb.SetStunMessage(SMRequest).AddFingerprint(true)
	sp := spb.Build()
	ba := sp.GetBytes()
	ba[len(ba)-2] = 2

	assert.True(t, sp.HasFingerPrint())
	assert.False(t, VerifyFingerPrint(*sp))
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

func TestBadStunPacket(t *testing.T) {
	ba := make([]byte, 20)
	sp, err := NewStunPacket(ba)
	assert.True(t, sp == nil)
	assert.Equal(t, "Not a valid stun packet!", err.Error())
}

func TestNoAddr(t *testing.T) {
	sp := NewStunPacketBuilder().Build()
	add, err := sp.GetAddress()
	assert.True(t, add == nil)
	assert.Equal(t, "MappedAddress Not found!", err.Error())
}

func TestToBuilderWithAddr(t *testing.T) {
	ip, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetAddress(ip).SetXORAddress(ip)
	sp := spb.Build()
	spb2 := sp.ToBuilder()
	sp2 := spb2.Build()
	a1, _ := sp.GetAddress()
	a2, _ := sp2.GetAddress()
	assert.Equal(t, a1, a2)
}

func BenchmarkStunParse(b *testing.B) {
	SP1, err := hex.DecodeString(SPRESP1)
	if err != nil {
		fmt.Println(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NewStunPacket(SP1)
	}
}

func BenchmarkStunParseAddress(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetTXID(CreateTID()).SetAddress(ip)
	sp := spb.Build()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sp.GetAddress()
	}
}

func BenchmarkStunParseXORAddress(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetTXID(CreateTID()).SetXORAddress(ip)
	sp := spb.Build()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sp.GetAddress()
	}
}

func BenchmarkCreateRequest(b *testing.B) {
	txid := CreateTID()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NewStunPacketBuilder().SetTXID(txid).Build()
	}
}

func BenchmarkBuildRequest(b *testing.B) {
	spb := NewStunPacketBuilder().SetTXID(CreateTID())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		spb.Build()
	}
}

func BenchmarkBuildResponse(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp4", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetTXID(CreateTID()).SetStunMessage(SMSuccess).SetAddress(ip).SetXORAddress(ip)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		spb.Build()
	}
}

func BenchmarkAddAddress4(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp4", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetTXID(CreateTID())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		spb.SetAddress(ip)
	}
}

func BenchmarkAddXORAddress4(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp4", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	spb := NewStunPacketBuilder().SetTXID(CreateTID())

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		spb.SetXORAddress(ip)
	}
}

func BenchmarkXORMap4(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp4", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
	}
	txid := CreateTID()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CreateMaskedAddress(*txid, ip)
	}
}

func BenchmarkXORMap6(b *testing.B) {
	ip, err := net.ResolveUDPAddr("udp6", "[fdda:701b:7be9:efd:0:0:0:af32]:8080")
	if err != nil {
		fmt.Println(err)
	}
	txid := CreateTID()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CreateMaskedAddress(*txid, ip)
	}
}

func BenchmarkCreateTID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		CreateTID()
	}
}
