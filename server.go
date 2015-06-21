// Package socks5 implements message marshalling and a server for the
// socks 5 protocol (RFC 1928).
//
// So far, only the CONNECT request is supported, and only the "No
// authentication required" method is supported for authentication.
//
// The Server interface is defined to allow different backends to be
// used for establishing connections. Users interested primarily in
// writing servers need only concern themselves with that interface,
// and the functions Serve/ListenAndServe.
//
// The message marshalling is also exposed, in the hopes that it may be
// useful.
package socks5 // import "zenhack.net/go/socks5"

import (
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

// The Dialer interface provides the ability to establish network
// connections. The Dial method works the same way as the Dial function
// from the net package.
type Dialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}

// A server handles socks requests. Right now this is equivalent to a
// Dialer; in the future more methods may be needed to support requests
// other than CONNECT.
type Server interface {
	Dialer
}

// Listen on the address addr and then accept connections, as with
// the Serve function.
func ListenAndServe(s Server, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return Serve(s, listener)
}

// Accept connections via l and, invoke the server s to handle them.
// Spawn a new goroutine for each request.
func Serve(s Server, l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleConn(s, conn)
	}
}

// Build a reply message based on err and the information provided by
// `conn`. `conn` may be nil if err is non-nil.
func makeReply(conn net.Conn, err error) *Msg {
	if err != nil {
		return &Msg{Code: ReplyError(err)}
	}

	addrStr := conn.LocalAddr().String()
	// The contract of conn.LocalAddr().String() requires that addrStr
	// is valid, therefore we can neglect the possibility of parse errors
	// in the below:
	hostStr, portStr, _ := net.SplitHostPort(addrStr)
	port, _ := strconv.Atoi(portStr)

	rep := &Msg{
		Code: byte(REP_SUCCESS),
		Port: uint16(port),
	}
	rep.Addr.IPAddr = net.ParseIP(hostStr)
	if rep.Addr.IPAddr == nil {
		rep.Addr = Address{
			Atyp:       ATYP_DOMAINNAME,
			DomainName: hostStr,
		}
	} else if len(rep.Addr.IPAddr) == 4 {
		rep.Addr.Atyp = ATYP_IPV4
	} else {
		rep.Addr.Atyp = ATYP_IPV6
	}
	return rep
}

// Copy data between a and b (both ways) concurrently.
func doCopy(a, b io.ReadWriter) {
	done := make(chan byte)
	go func() {
		io.Copy(a, b)
		done <- 0
	}()
	io.Copy(b, a)
	<-done
}

// Handle the socks connection conn using the server s
func handleConn(s Server, conn net.Conn) {
	err := authConn(conn)
	if err != nil {
		log.Println("Error authenticating client: ", err)
		return
	}
	req := &Msg{}
	_, err = req.ReadFrom(conn)
	if err != nil {
		log.Println("Error reading request: ", err)
		return
	}
	switch req.Code {
	case REQ_CONNECT:
		socksConn, err := s.Dial("tcp", net.JoinHostPort(
			req.Addr.String(),
			strconv.Itoa(int(req.Port)),
		))
		rep := makeReply(socksConn, err)
		rep.WriteTo(conn)
		if err != nil {
			log.Println("Error handling request: ", err)
			return
		}
		doCopy(conn, socksConn)
		conn.Close()
		socksConn.Close()
	default:
		(&Msg{Code: byte(REP_CMD_NOT_SUPPORTED)}).WriteTo(conn)
		log.Println("Command not supported: ", req.Code)
	}
}

// Do the authentication handshake. Right now we only support NO_AUTH_REQUIRED.
func authConn(conn net.Conn) error {
	buf := make([]byte, 255)
	_, err := conn.Read(buf[:2])
	if err != nil {
		return err
	}
	if buf[0] != VER {
		return BadVer
	}
	nmethods := buf[1]
	_, err = conn.Read(buf[:nmethods])
	if err != nil {
		return err
	}
	for i := range buf {
		if buf[i] == NO_AUTH_REQUIRED {
			_, err = conn.Write([]byte{VER, NO_AUTH_REQUIRED})
			return err
		}
	}
	conn.Write([]byte{VER, NO_ACCEPTABLE_METHODS})
	return errors.New("Client did not list NO_AUTH_REQUIRED as acceptable.")
}
