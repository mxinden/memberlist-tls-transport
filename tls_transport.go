// Fork of https://github.com/hashicorp/memberlist/blob/master/net_transport.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"bufio"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	// "github.com/armon/go-metrics"
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

func (t *TLSTransport) registerMetrics(reg prometheus.Registerer) {
	t.tcpConnEstablished = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "memberlist_tls_transport_tcp_conn_established",
		Help: "Amount of tcp connections established for memberlist's tls transport layer.",
	})

	reg.MustRegister(t.tcpConnEstablished)
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

// See Transport.
func (t *TLSTransport) WriteTo(b []byte, addr string) (time.Time, error) {

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
		return time.Time{}, err
	}
	defer conn.Close()

	t.tcpConnEstablished.Inc()

	// Signal that this is a packet connection.
	conn.Write([]byte{'p', '\n'})

	// TODO: This might only be the private, not the public address. We should
	// probably send the advertise address down the wire.
	conn.Write([]byte(t.tcpListeners[0].Addr().String()))
	conn.Write([]byte{'\n'})

	_, err = conn.Write(b)
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
		return nil, err
	}

	t.tcpConnEstablished.Inc()

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
	}

	// Block until all the listener threads have died.
	t.wg.Wait()
	return nil
}

// tcpListen is a long running goroutine that accepts incoming TCP connections
// and hands them off to the stream channel.
func (t *TLSTransport) tcpListen(ln net.Listener) {
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

		reader := bufio.NewReader(conn)

		connType, err := reader.ReadString('\n')
		if err != nil {
			t.logger.Fatalf("failed to read connection type: %v", err)
		}
		connType = strings.Trim(connType, "\n")

		if connType == "p" {
			defer conn.Close()

			remoteAddr, err := reader.ReadString('\n')
			if err != nil {
				t.logger.Fatalf("failed to read remote address: %v", err)
			}

			remoteAddr = strings.Trim(remoteAddr, "\n")

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

			msg, err := ioutil.ReadAll(conn)
			if err != nil {
				t.logger.Fatal(err)
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
