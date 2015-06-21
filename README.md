A Go library for writing SOCKS 5 servers. (RFC 1928)

So far, only the `CONNECT` request is supported, and only the "No
authentication required" method is supported for authentication.

The `Server` interface is defined to allow different backends to be
used for establishing connections. The message marshalling is also
exposed, in the hopes that it may be useful.

There is also an example server that just makes connections from the
local machine when servicing requests in `cmd/socks5d`.

This package must be imported by the canonical path 
`zenhack.net/go/socks5`; using the Github URL will not work.

# LICENSE

Free/Open Source under the MIT license (see `COPYING`)
