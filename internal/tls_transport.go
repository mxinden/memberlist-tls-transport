package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	// "github.com/armon/go-metrics"
	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/memberlist"
)

const (
	// udpPacketBufSize is used to buffer incoming packets during read
	// operations.
	udpPacketBufSize = 65536

	// udpRecvBufSize is a large buffer size that we attempt to set UDP
	// sockets to in order to handle a large volume of messages.
	udpRecvBufSize = 2 * 1024 * 1024
)

// NetTransportConfig is used to configure a net transport.
type NetTransportConfig struct {
	// BindAddrs is a list of addresses to bind to for both TCP and UDP
	// communications.
	BindAddrs []string

	// BindPort is the port to listen on, for each address above.
	BindPort int

	// Logger is a logger for operator messages.
	Logger *log.Logger
}

// NetTransport is a Transport implementation that uses connectionless UDP for
// packet operations, and ad-hoc TCP connections for stream operations.
type NetTransport struct {
	config       *NetTransportConfig
	packetCh     chan *memberlist.Packet
	streamCh     chan net.Conn
	logger       *log.Logger
	wg           sync.WaitGroup
	tcpListeners []net.Listener
	udpListeners []net.Listener
	shutdown     int32
}

// NewNetTransport returns a net transport with the given configuration. On
// success all the network listeners will be created and listening.
func NewNetTransport(config *NetTransportConfig) (*NetTransport, error) {
	// If we reject the empty list outright we can assume that there's at
	// least one listener of each type later during operation.
	if len(config.BindAddrs) == 0 {
		return nil, fmt.Errorf("At least one bind address is required")
	}

	// Build out the new transport.
	var ok bool
	t := NetTransport{
		config:   config,
		packetCh: make(chan *memberlist.Packet),
		streamCh: make(chan net.Conn),
		logger:   config.Logger,
	}

	// Clean up listeners if there's an error.
	defer func() {
		if !ok {
			t.Shutdown()
		}
	}()

	// Build all the TCP and UDP listeners.
	port := config.BindPort
	for _, addr := range config.BindAddrs {
		ip := net.ParseIP(addr)

		cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
		if err != nil {
			return nil, fmt.Errorf("%v", err)
		}

		tcpAddr := &net.TCPAddr{IP: ip, Port: port}
		tcpLn, err := tls.Listen("tcp", tcpAddr.String(), &tls.Config{
			Certificates: []tls.Certificate{cer},
		})
		if err != nil {
			return nil, fmt.Errorf("Failed to start TLS listener on %q port %d: %v", addr, port, err)
		}
		t.tcpListeners = append(t.tcpListeners, tcpLn)

		// If the config port given was zero, use the first TCP listener
		// to pick an available port and then apply that to everything
		// else.
		if port == 0 {
			port = tcpLn.Addr().(*net.TCPAddr).Port
		}

		// TODO: Fix var names.
		// TODO: Don't just increase port by 3.
		udpAddr := &net.TCPAddr{IP: ip, Port: port + 3}
		udpLn, err := tls.Listen("tcp", udpAddr.String(), &tls.Config{
			Certificates: []tls.Certificate{cer},
		})
		if err != nil {
			return nil, fmt.Errorf("Failed to start TLS packed oriented listener on %q port %d: %v", addr, port, err)
		}
		// TODO: Is this still needed?
		// if err := setUDPRecvBuf(udpLn); err != nil {
		// 	return nil, fmt.Errorf("Failed to resize UDP buffer: %v", err)
		// }
		t.udpListeners = append(t.udpListeners, udpLn)
	}

	// Fire them up now that we've been able to create them all.
	for i := 0; i < len(config.BindAddrs); i++ {
		t.wg.Add(2)
		go t.tcpListen(t.tcpListeners[i])
		go t.udpListen(t.udpListeners[i])
	}

	ok = true
	return &t, nil
}

// GetAutoBindPort returns the bind port that was automatically given by the
// kernel, if a bind port of 0 was given.
func (t *NetTransport) GetAutoBindPort() int {
	// We made sure there's at least one TCP listener, and that one's
	// port was applied to all the others for the dynamic bind case.
	return t.tcpListeners[0].Addr().(*net.TCPAddr).Port
}

// See Transport.
func (t *NetTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	var advertiseAddr net.IP
	var advertisePort int
	if ip != "" {
		// If they've supplied an address, use that.
		advertiseAddr = net.ParseIP(ip)
		if advertiseAddr == nil {
			return nil, 0, fmt.Errorf("Failed to parse advertise address %q", ip)
		}

		// Ensure IPv4 conversion if necessary.
		if ip4 := advertiseAddr.To4(); ip4 != nil {
			advertiseAddr = ip4
		}
		advertisePort = port
	} else {
		if t.config.BindAddrs[0] == "0.0.0.0" {
			// Otherwise, if we're not bound to a specific IP, let's
			// use a suitable private IP address.
			var err error
			ip, err = sockaddr.GetPrivateIP()
			if err != nil {
				return nil, 0, fmt.Errorf("Failed to get interface addresses: %v", err)
			}
			if ip == "" {
				return nil, 0, fmt.Errorf("No private IP address found, and explicit IP not provided")
			}

			advertiseAddr = net.ParseIP(ip)
			if advertiseAddr == nil {
				return nil, 0, fmt.Errorf("Failed to parse advertise address: %q", ip)
			}
		} else {
			// Use the IP that we're bound to, based on the first
			// TCP listener, which we already ensure is there.
			advertiseAddr = t.tcpListeners[0].Addr().(*net.TCPAddr).IP
		}

		// Use the port we are bound to.
		advertisePort = t.GetAutoBindPort()
	}

	return advertiseAddr, advertisePort, nil
}

// See Transport.
func (t *NetTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	roots := x509.NewCertPool()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: roots,
		// TODO: Remove InsecureSkipVerify.
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.logger.Println(err)
		return time.Time{}, err
	}

	defer conn.Close()

	// Signal that this is a packet connection.
	conn.Write([]byte{'p'})

	conn.Write([]byte(strconv.Itoa(t.config.BindPort)))

	_, err = conn.Write(b)
	if err != nil {
		t.logger.Println(err)
		return time.Time{}, err
	}

	return time.Now(), nil
}

// See Transport.
func (t *NetTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// See Transport.
func (t *NetTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	roots := x509.NewCertPool()

	// TODO: What about dialer timeout like:
	// dialer := net.Dialer{Timeout: timeout}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: roots,
		// TODO: Remove InsecureSkipVerify.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	// Signal that this is a stream connection.
	_, err = conn.Write([]byte{'s'})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// See Transport.
func (t *NetTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// See Transport.
func (t *NetTransport) Shutdown() error {
	// This will avoid log spam about errors when we shut down.
	atomic.StoreInt32(&t.shutdown, 1)

	// Rip through all the connections and shut them down.
	for _, conn := range t.tcpListeners {
		conn.Close()
	}
	for _, conn := range t.udpListeners {
		conn.Close()
	}

	// Block until all the listener threads have died.
	t.wg.Wait()
	return nil
}

// tcpListen is a long running goroutine that accepts incoming TCP connections
// and hands them off to the stream channel.
func (t *NetTransport) tcpListen(ln net.Listener) {
	defer t.wg.Done()
	for {
		ts := time.Now()
		conn, err := ln.Accept()
		if err != nil {
			if s := atomic.LoadInt32(&t.shutdown); s == 1 {
				break
			}

			t.logger.Printf("[ERR] memberlist: Error accepting TCP connection: %v", err)
			continue
		}

		b := make([]byte, 1)

		if _, err := conn.Read(b); err != nil {
			t.logger.Fatal(err)
		}

		if b[0] == 'p' {
			defer conn.Close()

			remotePort := make([]byte, 4)
			if _, err := conn.Read(remotePort); err != nil {
				t.logger.Fatal(err)
			}

			parsedPort, err := strconv.Atoi(string(remotePort))
			if err != nil {
				t.logger.Fatal(err)
			}

			msg, err := ioutil.ReadAll(conn)
			if err != nil {
				t.logger.Fatal(err)
			}

			addr := &net.TCPAddr{
				IP:   []byte{127, 0, 0, 1},
				Port: parsedPort,
			}

			// TODO: Should we still increase these metrics?
			// metrics.IncrCounter([]string{"memberlist", "udp", "received"}, float32(n))
			t.packetCh <- &memberlist.Packet{
				Buf:       msg,
				From:      addr,
				Timestamp: ts,
			}
		} else {
			t.streamCh <- conn
		}
	}
}

// udpListen is a long running goroutine that accepts incoming UDP packets and
// hands them off to the packet channel.
func (t *NetTransport) udpListen(udpLn net.Listener) {
	defer t.wg.Done()

	for {
		ts := time.Now()

		conn, err := udpLn.Accept()
		if err != nil {
			t.logger.Fatal(err)
		}

		t.logger.Fatalf("got something on pseudo udp port from %v", conn.RemoteAddr().String())

		go func(conn net.Conn, startTime time.Time) {
			defer conn.Close()

			msg, err := ioutil.ReadAll(conn)
			if err != nil {
				t.logger.Fatal(err)
			}

			t.logger.Printf("Read: %q", msg)

			// TODO: Should we still increase these metrics?
			// metrics.IncrCounter([]string{"memberlist", "udp", "received"}, float32(n))
			t.packetCh <- &memberlist.Packet{
				Buf:       msg,
				From:      conn.RemoteAddr(),
				Timestamp: startTime,
			}
		}(conn, ts)
	}
}

// setUDPRecvBuf is used to resize the UDP receive window. The function
// attempts to set the read buffer to `udpRecvBuf` but backs off until
// the read buffer can be set.
func setUDPRecvBuf(c *net.UDPConn) error {
	size := udpRecvBufSize
	var err error
	for size > 0 {
		if err = c.SetReadBuffer(size); err == nil {
			return nil
		}
		size = size / 2
	}
	return err
}
