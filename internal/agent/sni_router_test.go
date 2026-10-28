package agent

import (
	"bytes"
	"testing"
)

func TestExtractSNI(t *testing.T) {
	// 构造一个包含 SNI "hk.forward.com" 的合法 TLS ClientHello 包
	sniHost := "hk.forward.com"
	clientHello := buildMockClientHello(sniHost)

	sni, ok := extractSNI(clientHello)
	if !ok {
		t.Fatalf("expected extractSNI to succeed, got false")
	}
	if sni != sniHost {
		t.Fatalf("expected SNI %s, got %s", sniHost, sni)
	}

	// 测试非 TLS 数据 (如普通 HTTP 请求)
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, ok = extractSNI(httpReq)
	if ok {
		t.Fatalf("expected HTTP request to fail SNI extraction")
	}

	// 测试无 SNI 的 TLS 握手 (直接以 IP 握手)
	tlsWithoutSNI := buildMockClientHelloWithoutSNI()
	_, ok = extractSNI(tlsWithoutSNI)
	if ok {
		t.Fatalf("expected TLS without SNI to return false")
	}
}

// 辅助函数：构造测试用的 TLS ClientHello 字节流
func buildMockClientHello(sni string) []byte {
	var body bytes.Buffer

	// Client Version: TLS 1.2 (0x03, 0x03)
	body.Write([]byte{0x03, 0x03})
	// Random (32 bytes)
	body.Write(make([]byte, 32))
	// Session ID Length (0)
	body.WriteByte(0x00)
	// Cipher Suites Length (2) + Cipher (0x13, 0x01)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	// Compression Methods Length (1) + Method (0x00)
	body.Write([]byte{0x01, 0x00})

	// Extensions
	var extBuf bytes.Buffer

	// Server Name Extension (Type 0x0000)
	sniBytes := []byte(sni)
	nameLen := len(sniBytes)
	listLen := nameLen + 3
	extLen := listLen + 2

	extBuf.Write([]byte{0x00, 0x00})                                // Extension Type: server_name
	extBuf.Write([]byte{byte(extLen >> 8), byte(extLen & 0xff)})    // Extension Length
	extBuf.Write([]byte{byte(listLen >> 8), byte(listLen & 0xff)})  // Server Name List Length
	extBuf.WriteByte(0x00)                                          // Name Type: host_name (0)
	extBuf.Write([]byte{byte(nameLen >> 8), byte(nameLen & 0xff)})  // Name Length
	extBuf.Write(sniBytes)                                          // HostName

	// Extensions Total Length
	body.Write([]byte{byte(extBuf.Len() >> 8), byte(extBuf.Len() & 0xff)})
	body.Write(extBuf.Bytes())

	// Handshake Header
	var handshake bytes.Buffer
	handshake.WriteByte(0x01) // Handshake Type: ClientHello
	handshakeLen := body.Len()
	handshake.Write([]byte{byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen & 0xff)})
	handshake.Write(body.Bytes())

	// Record Header
	var record bytes.Buffer
	record.WriteByte(0x16)         // ContentType: Handshake
	record.Write([]byte{0x03, 0x01}) // Version: TLS 1.0 (Record layer standard)
	recLen := handshake.Len()
	record.Write([]byte{byte(recLen >> 8), byte(recLen & 0xff)})
	record.Write(handshake.Bytes())

	return record.Bytes()
}

func buildMockClientHelloWithoutSNI() []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{0x00, 0x00}) // 0 extensions

	var handshake bytes.Buffer
	handshake.WriteByte(0x01)
	handshakeLen := body.Len()
	handshake.Write([]byte{byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen & 0xff)})
	handshake.Write(body.Bytes())

	var record bytes.Buffer
	record.WriteByte(0x16)
	record.Write([]byte{0x03, 0x01})
	recLen := handshake.Len()
	record.Write([]byte{byte(recLen >> 8), byte(recLen & 0xff)})
	record.Write(handshake.Bytes())

	return record.Bytes()
}
