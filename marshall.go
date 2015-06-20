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
	NO_AUTH_REQUIRED  = 0x0
	GSSAPI            = 0x1
	USERNAME_PASSWORD = 0x2

	NO_ACCEPTABLE_METHODS = 0xff

	// Requests:
	REQ_CONNECT       = 0x1
	REQ_BIND          = 0x2
	REQ_UDP_ASSOCIATE = 0x3

	// Address types:
	ATYP_IPV4       = 0x1
	ATYP_DOMAINNAME = 0x03
	ATYP_IPV6       = 0x4

	// Replies:
	REP_SUCCESS                = ReplyCode(0x0)
	REP_GENERAL_SERVER_FAILURE = ReplyCode(0x1)
	REP_CONNECTION_NOT_ALLOWED = ReplyCode(0x2)
	REP_NETWORK_UNREACHABLE    = ReplyCode(0x3)
	REP_HOST_UNREACHABLE       = ReplyCode(0x4)
	REP_CONNECTION_REFUSED     = ReplyCode(0x5)
	REP_TTL_EXPIRED            = ReplyCode(0x6)
	REP_CMD_NOT_SUPPORTED      = ReplyCode(0x7)
	REP_ATYP_NOT_SUPPORTED     = ReplyCode(0x8)
)

var (
	// Marshalling related errors
	BadVer  = errors.New("Unexpected version number (expected 5)")
	BadRsv  = errors.New("Reserved field was not zero.")
	BadAtyp = errors.New("Unsupported address address type")
	BadStr  = errors.New("String too long (max 255 chars)")
)

// Returns an error code corresponding to the error "err". If err is of
// type ReplyCode, ReplyError returns err. If err is nil, ReplyError returns
// REP_SUCCESS. Otherwise, ReplyError returns REP_GENERAL_SERVER_FAILURE.
func ReplyError(err error) byte {
	if err == nil {
		return byte(REP_SUCCESS)
	}
	code, ok := err.(ReplyCode)
	if !ok {
		return byte(REP_GENERAL_SERVER_FAILURE)
	}
	return byte(code)
}

// helper function to keep things concise in the WriteTo methods
// for Address and Msg.
func writeHelper(n *int64, err *error, w io.Writer, p []byte) {
	if *err == nil {
		var written int
		written, *err = w.Write(p)
		*n += int64(written)
	}
}

// An IP address or domain name as used by the socks protocol
type Address struct {
	Atyp   byte   // The address type; one of the ATYP_* constants above.
	IPAddr net.IP // used if Atyp is *not* ATYP_DOMAINNAME

	// used if Atyp *is* ATYP_DOMAINNAME. This must be at a maximum 255
	// characters, as only one byte is used to encode the length:
	DomainName string
}

// Read an address, including the address type byte, from the reader r.
func (a *Address) ReadFrom(r io.Reader) (n int64, err error) {
	var buf []byte
	var count int
	readIp := func() {
		count, err = r.Read(buf)
		n += int64(count)
		a.IPAddr = buf
	}
	buf = []byte{0}
	count, err = r.Read(buf)
	n += int64(count)
	if err != nil {
		return
	}
	a.Atyp = buf[0]
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

// Write the address (including the Atyp byte) to the writer w
func (a *Address) WriteTo(w io.Writer) (n int64, err error) {
	write := func(p []byte) { writeHelper(&n, &err, w, p) }
	write([]byte{a.Atyp})
	if a.Atyp == ATYP_DOMAINNAME {
		size := len(a.DomainName)
		if size >= (1 << 8) {
			return n, BadStr
		}
		write([]byte{byte(size)})
		write([]byte(a.DomainName))
	} else {
		write(a.IPAddr)
	}
	return
}

// Format the address as a string suitable for use as the host part of
// the address string passed to a Dialer (sans brackets for ipv6).
func (a Address) String() string {
	if a.Atyp == ATYP_DOMAINNAME {
		return a.DomainName
	} else {
		return a.IPAddr.String()
	}
}

// A socks5 protocol message (either a request or a reply)
type Msg struct {
	Code byte // CMD for requests, REP for replies
	Addr Address
	Port uint16
}

// Read a message from the reader r
func (m *Msg) ReadFrom(r io.Reader) (n int64, err error) {
	var count int
	buf := make([]byte, 3)
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

// Write the message to the writer w
func (m *Msg) WriteTo(w io.Writer) (n int64, err error) {
	write := func(p []byte) { writeHelper(&n, &err, w, p) }
	write([]byte{VER, byte(m.Code), 0})
	count, err := m.Addr.WriteTo(w)
	n += int64(count)
	if err != nil {
		return
	}
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, m.Port)
	write(port)
	return
}

// An error representable in the socks 5 protocol's reply field
type ReplyCode byte

func (c ReplyCode) Error() string {
	return []string{
		"success",
		"general server failure",
		"connection not allowed",
		"network unreachable",
		"host unreachable",
		"connection refused",
		"ttl expired",
		"command not supported",
		"address type not supported",
	}[c]
}
