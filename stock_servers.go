package socks5

import (
	"net"
)

// PassThroughDialer invokes the net package's Dial function
var PassThroughDialer Dialer = passThroughDialer{}

type passThroughDialer struct{}

func (d passThroughDialer) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}
