package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	VER = 5

	// Authentication types:
	NO_AUTH_REQUIRED = 0x0
	GSSAPI = 0x1
	USERNAME_PASSWORD = 0x2

	NO_ACCEPTABLE_METHODS = 0xff

	// Requests:
	REQ_CONNECT = 0x1
	REQ_BIND = 0x2
	REQ_UDP_ASSOCIATE = 0x3

	// Address types:
	ATYP_IPV4 = 0x1
	ATYP_DOMAINNAME = 0x03
	ATYP_IPV6 = 0x4

	// Replies:
	REP_SUCCESS = 0x0
	REP_GENERAL_SERVER_FAILURE = 0x1
	REP_CONNECTION_NOT_ALLOWED = 0x2
	REP_NETWORK_UNREACHABLE = 0x3
	REP_HOST_UNREACHABLE = 0x4
	REP_CONNECTION_REFUSED = 0x5
	REP_TTL_EXPIRED = 0x6
	REP_CMD_NOT_SUPPORTED = 0x7
	REP_ATYP_NOT_SUPPORTED = 0x8
)

var (
	BadVer  = errors.New("Unexpected version number (expected 5)")
	BadRsv  = errors.New("Reserved field was not zero.")
	BadAtyp = errors.New("Unsupported address address type")
	BadStr  = errors.New("String too long")
)

type Address struct {
	Atyp byte
	IPAddr net.IP // used if Atyp is *not* ATYP_DOMAINNAME
	DomainName string // used if Atyp *is* ATYP_DOMAINNAME
}

func (a Address) ReadFrom(r io.Reader) (n int64, err error) {
	var buf []byte
	var count int
	readIp := func() {
		count, err = r.Read(buf)
		n += int64(count)
		a.IPAddr = buf
	}
	switch a.Atyp {
	case ATYP_IPV4:
		buf = make([]byte, 4)
		readIp()
	case ATYP_IPV6:
		buf = make([]byte, 16)
		readIp()
	case ATYP_DOMAINNAME:
		buf = []byte{0}
		count, err = r.Read(buf)
		n += int64(count)
		if err != nil {
			return
		}
		name_len := buf[0]
		buf = make([]byte, name_len)
		count, err = r.Read(buf)
		n += int64(count)
		if err != nil {
			return
		}
		a.DomainName = string(buf)
	default:
		return n, BadAtyp
	}
	return
}

type Msg struct {
	Code byte // CMD for requests, REP for replies
	Addr Address
	Port uint16
}

func (m *Msg) ReadFrom(r io.Reader) (n int64, err error) {
	var count int
	buf := make([]byte, 4)
	count, err = r.Read(buf)
	n += int64(count)
	if err != nil {
		return
	}
	if buf[0] != VER {
		return n, BadVer
	}
	m.Code = buf[1]
	if buf[2] != 0 {
		return n, BadRsv
	}
	m.Addr.Atyp = buf[3]
	count2, err := m.Addr.ReadFrom(r)
	n += count2
	if err != nil {
		return
	}

	buf = make([]byte, 2)
	count, err = r.Read(buf)
	n += int64(count)
	if err != nil {
		return
	}
	m.Port = binary.BigEndian.Uint16(buf)
	return
}

func (m *Msg) WriteTo(w io.Writer) (n int64, err error) {
	write := func (p []byte) {
		if err == nil {
			var written int
			written, err = w.Write(p)
			n += int64(written)
		}
	}

	write([]byte{VER, m.Code, 0, m.Addr.Atyp})
	if m.Addr.Atyp == ATYP_DOMAINNAME {
		size := len(m.Addr.DomainName)
		if size > (1<<7) {
			return n, BadStr
		}
		write([]byte{byte(size)})
		write([]byte(m.Addr.DomainName))
	} else {
		write(m.Addr.IPAddr)
	}
	port := []byte{0,0}
	binary.BigEndian.PutUint16(port, m.Port)
	write(port)
	return
}
