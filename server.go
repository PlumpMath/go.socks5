package socks5

import (
	"errors"
	"io"
	"log"
	"net"
)

type Conn interface {
	io.Reader
	io.Writer
	io.Closer
}

type Server interface {
	Connect(req *Msg) (rep *Msg, c Conn, err error)
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
		rep, socksConn, err := s.Connect(req)
		rep.WriteTo(conn)
		if err != nil {
			log.Println("Error handling request: ", err)
		}
		if rep.Code == REP_SUCCESS {
			done := make(chan byte)
			go func(){
				io.Copy(conn, socksConn)
				done <- 0
			}()
			io.Copy(socksConn, conn)
			<-done
		}
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
	for i := range(buf) {
		if buf[i] == NO_AUTH_REQUIRED {
			_, err = conn.Write([]byte{VER, NO_AUTH_REQUIRED})
			return err
		}
	}
	conn.Write([]byte{VER, NO_ACCEPTABLE_METHODS})
	return errors.New("Client did not list NO_AUTH_REQUIRED as acceptable.")
}
