package socks5

import (
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

type Dialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}

type Server interface {
	Dialer
}

func Serve(s Server, l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleConn(s, conn)
	}
}

func ListenAndServe(s Server, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return Serve(s, listener)
}

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

func doCopy(a, b io.ReadWriteCloser) {
	done := make(chan byte)
	go func() {
		io.Copy(a, b)
		done <- 0
	}()
	io.Copy(b, a)
	<-done
}

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
	default:
		(&Msg{Code: byte(REP_CMD_NOT_SUPPORTED)}).WriteTo(conn)
		log.Println("Command not supported: ", req.Code)
	}
}

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
