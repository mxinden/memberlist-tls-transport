// Fork of https://github.com/hashicorp/memberlist/blob/master/net_transport.go

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// "github.com/armon/go-metrics"
	"github.com/golang/groupcache/lru"
	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/memberlist"
	"github.com/prometheus/client_golang/prometheus"
)

// TLSTransportConfig is used to configure a net transport.
type TLSTransportConfig struct {
	// BindAddrs is a list of addresses to bind to for both TCP and UDP
	// communications.
	BindAddrs []string

	// BindPort is the port to listen on, for each address above.
	BindPort int

	// Logger is a logger for operator messages.
	Logger *log.Logger
}

// TLSTransport is a Transport implementation that uses connectionless UDP for
// packet operations, and ad-hoc TCP connections for stream operations.
type TLSTransport struct {
	config       *TLSTransportConfig
	packetCh     chan *memberlist.Packet
	streamCh     chan net.Conn
	logger       *log.Logger
	wg           sync.WaitGroup
	tcpListeners []net.Listener
	shutdown     int32

	tcpConnEstablished prometheus.Counter
	tcpConnClosed      prometheus.Counter

	// Don't use RWMutex. connPool.Get records the recent usage, hence
	// concurrent Gets are not safe.
	connPoolLock sync.Mutex
	connPool     *lru.Cache
}

// NewTLSTransport returns a net transport with the given configuration. On
// success all the network listeners will be created and listening.
func NewTLSTransport(config *TLSTransportConfig, reg prometheus.Registerer) (*TLSTransport, error) {
	// If we reject the empty list outright we can assume that there's at
	// least one listener of each type later during operation.
	if len(config.BindAddrs) == 0 {
		return nil, fmt.Errorf("At least one bind address is required")
	}

	// Build out the new transport.
	var ok bool
	t := TLSTransport{
		config:   config,
		packetCh: make(chan *memberlist.Packet),
		streamCh: make(chan net.Conn),
		logger:   config.Logger,
		// TODO: How about using the current instance count here instead? Should
		// probably be a safe default.
		connPool: lru.New(5),
	}

	t.connPool.OnEvicted = func(key lru.Key, conn interface{}) {
		fmt.Printf("evicting connection: %v", key)
		err := conn.(net.Conn).Close()
		if err != nil {
			log.Fatalf("failed to close tls connection triggered by lru cache evection: %v", err)
		}

		t.tcpConnClosed.Inc()
	}

	t.registerMetrics(reg)

	// Clean up listeners if there's an error.
	defer func() {
		if !ok {
			t.Shutdown()
		}
	}()

	// Build all the TCP listeners.
	port := config.BindPort
	for _, addr := range config.BindAddrs {
		ip := net.ParseIP(addr)

		// Generated via https://github.com/wolfeidau/golang-massl
		caCert, err := ioutil.ReadFile("./certs/ca.pem")
		if err != nil {
			log.Fatalf("failed to load cert: %s", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		cert, err := tls.LoadX509KeyPair("./certs/server.pem", "./certs/server-key.pem")
		if err != nil {
			return nil, fmt.Errorf("%v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},        // server certificate which is validated by the client
			ClientCAs:    caCertPool,                     // used to verify the client cert is signed by the CA and is therefore valid
			ClientAuth:   tls.RequireAndVerifyClientCert, // this requires a valid client certificate to be supplied during handshake
		}

		tcpAddr := &net.TCPAddr{IP: ip, Port: port}
		tcpLn, err := tls.Listen("tcp", tcpAddr.String(), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("Failed to start TLS listener on %q port %d: %v", addr, port, err)
		}
		t.tcpListeners = append(t.tcpListeners, tcpLn)
	}

	// Fire them up now that we've been able to create them all.
	for i := 0; i < len(config.BindAddrs); i++ {
		t.wg.Add(1)
		go t.tcpListen(t.tcpListeners[i])
	}

	ok = true
	return &t, nil
}

// TODO: Rework metric descriptions.
func (t *TLSTransport) registerMetrics(reg prometheus.Registerer) {
	t.tcpConnEstablished = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "memberlist_tls_transport_tcp_conn_established",
		Help: "Amount of tcp connections established for memberlist's tls transport layer.",
	})

	t.tcpConnClosed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "memberlist_tls_transport_tcp_conn_closed",
		Help: "Amount of memberlist's tls transport layer connections closed either through shutdown or connection pool eviction.",
	})

	reg.MustRegister(t.tcpConnEstablished, t.tcpConnClosed)
}

// GetAutoBindPort returns the bind port that was automatically given by the
// kernel, if a bind port of 0 was given.
func (t *TLSTransport) GetAutoBindPort() int {
	// We made sure there's at least one TCP listener, and that one's
	// port was applied to all the others for the dynamic bind case.
	return t.tcpListeners[0].Addr().(*net.TCPAddr).Port
}

// See Transport.
func (t *TLSTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
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

func (t *TLSTransport) dial(addr string) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair("./certs/client.pem", "./certs/client-key.pem")

	caCert, err := ioutil.ReadFile("./certs/ca.pem")
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, // this certificate is used to sign the handshake
		RootCAs:      caCertPool,              // this is used to validate the server certificate
	}
	tlsConfig.BuildNameToCertificate()

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		t.logger.Println(err)
		return nil, err
	}

	t.tcpConnEstablished.Inc()

	return conn, nil
}

// See Transport.
func (t *TLSTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	var (
		conn net.Conn
		err  error
	)

	t.connPoolLock.Lock()

	fmt.Println("Getting connection for: ", addr)
	if c, ok := t.connPool.Get(addr); ok {
		conn = c.(net.Conn)
	} else {
		conn, err = t.dial(addr)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to create new packet connection: %v", err)
		}
		go t.readConn(addr, conn)
		t.logger.Printf("Adding new connection for: %q\n", addr)
		t.connPool.Add(addr, conn)

		// TODO: We should send a magicbyte signaling the protocol and a version
		// byte first before sending the connection type.
		// Signal that this is a packet connection.
		conn.Write([]byte{'p', '\n'})

		// TODO: This might only be the private, not the public address. We should
		// probably send the advertise address down the wire.
		conn.Write(append([]byte(t.tcpListeners[0].Addr().String()), '\n'))
	}

	t.connPoolLock.Unlock()

	// TODO: This is probably not performing very well. How about prefixing each msg
	// with a length and reading just as far as the length?
	msg := []byte(base64.StdEncoding.EncodeToString(b))
	msg = append(msg, '\n')

	// This connection might be shared among multiple goroutines. conn.Write is
	// thread safe. Make sure to write in one go so no concurrent write gets in
	// between.
	_, err = conn.Write(msg)
	if err != nil {
		t.logger.Println(err)
		return time.Time{}, err
	}

	return time.Now(), nil
}

// See Transport.
func (t *TLSTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// See Transport.
func (t *TLSTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := t.dial(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream connection: %v", err)
	}

	// Signal that this is a stream connection.
	_, err = conn.Write([]byte{'s', '\n'})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// See Transport.
func (t *TLSTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// See Transport.
func (t *TLSTransport) Shutdown() error {
	// This will avoid log spam about errors when we shut down.
	atomic.StoreInt32(&t.shutdown, 1)

	// Rip through all the connections and shut them down.
	for _, conn := range t.tcpListeners {
		conn.Close()
		t.tcpConnClosed.Inc()
	}

	// Block until all the listener threads have died.
	t.wg.Wait()
	return nil
}

func (t *TLSTransport) readConn(remoteAddr string, conn net.Conn) {
	host, portString, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		t.logger.Fatal(err)
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		t.logger.Fatal(err)
	}

	addr := &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}
	reader := bufio.NewReader(conn)

	for {
		msgB64, err := reader.ReadString('\n')
		if err != nil {
			t.logger.Fatalf("failed to read message from packet connection: %v", err)
		}
		ts := time.Now()

		msgB64 = strings.Trim(msgB64, "\n")

		msg, err := base64.StdEncoding.DecodeString(msgB64)
		if err != nil {
			t.logger.Fatalf("failed to base64 decode packet message: %v", err)
		}

		// TODO: Should we still increase these metrics?
		// metrics.IncrCounter([]string{"memberlist", "udp", "received"}, float32(n))
		t.packetCh <- &memberlist.Packet{
			Buf:       []byte(msg),
			From:      addr,
			Timestamp: ts,
		}
	}
}

// tcpListen is a long running goroutine that accepts incoming TCP connections
// and hands them off to either the stream or packet channel.
func (t *TLSTransport) tcpListen(ln net.Listener) {
	defer t.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s := atomic.LoadInt32(&t.shutdown); s == 1 {
				break
			}

			t.logger.Printf("[ERR] memberlist: Error accepting TCP connection: %v", err)
			continue
		}

		reader := bufio.NewReader(conn)

		connType, err := reader.ReadString('\n')
		if err != nil {
			t.logger.Fatalf("failed to read connection type: %v", err)
		}
		connType = strings.Trim(connType, "\n")

		if connType == "p" {
			remoteAddr, err := reader.ReadString('\n')
			if err != nil {
				t.logger.Fatalf("failed to read remote address: %v", err)
			}

			remoteAddr = strings.Trim(remoteAddr, "\n")

			go t.readConn(remoteAddr, conn)

			t.connPoolLock.Lock()
			t.logger.Printf("Adding connection for: %q\n", remoteAddr)
			// TODO: Check if the connection already exists, if so, the callback
			// is not called when overwriting the value.
			t.connPool.Add(remoteAddr, conn)
			t.connPoolLock.Unlock()
		} else {
			t.streamCh <- conn
		}
	}
}
