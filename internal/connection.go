package internal

import (
	"bufio"
	"encoding/base64"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/hashicorp/memberlist"
	"github.com/prometheus/client_golang/prometheus"
)

// TODO: Should this be a packet connection?
type Conn struct {
	conn       net.Conn
	done       chan struct{}
	closing    chan<- string
	packetCh   chan<- *memberlist.Packet
	remoteAddr *net.TCPAddr
	logger     *log.Logger
	incoming   bool
}

func NewConn(
	remoteAddr string,
	c net.Conn,
	packetCh chan<- *memberlist.Packet,
	closing chan<- string,
	logger *log.Logger,
	incoming bool,
) (*Conn, error) {
	host, portString, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}

	addr := &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}
	conn := &Conn{
		conn:       c,
		remoteAddr: addr,
		packetCh:   packetCh,
		closing:    closing,
		done:       make(chan struct{}),
		logger:     logger,
		incoming:   incoming,
	}

	go conn.read()

	return conn, nil
}

// We need to wait for any new incoming packets before closing.
func (c *Conn) CloseInABit() {
	go func() {
		time.Sleep(time.Minute)
		close(c.done)
		c.conn.Close()
	}()
}

// Incoming returns whether the connection is an incoming or an outgoing TCP
// connection.
func (c *Conn) IsIncoming() bool {
	return c.incoming
}

func (c *Conn) close() {
	c.closing <- c.remoteAddr.String()
}

func (c *Conn) read() {
	reader := bufio.NewReader(c.conn)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		msgB64, err := reader.ReadString('\n')
		if err != nil {
			c.logger.Printf("failed to read message from packet connection: %v", err)
			c.close()
			return
		}
		ts := time.Now()

		msgB64 = strings.Trim(msgB64, "\n")

		msg, err := base64.StdEncoding.DecodeString(msgB64)
		if err != nil {
			c.logger.Printf("failed to base64 decode packet message: %v", err)
			c.close()
			return
		}

		// TODO: Should we still increase these metrics?
		// metrics.IncrCounter([]string{"memberlist", "udp", "received"}, float32(n))
		c.packetCh <- &memberlist.Packet{
			Buf:       []byte(msg),
			From:      c.remoteAddr,
			Timestamp: ts,
		}
	}
}

type ConnPool struct {
	// Don't use RWMutex. connPool.Get records the recent usage, hence
	// concurrent Gets are not safe.
	//
	// TODO: Maybe this should be called packetConnPool, as it does not contain
	// stream connections.
	lock     sync.Mutex
	pool     *lru.Cache
	packetCh chan<- *memberlist.Packet
	closing  chan string
	logger   *log.Logger

	localAddr string

	connAddedToPool     prometheus.Counter
	connRemovedFromPool prometheus.Counter
}

func NewConnPool(
	packetCh chan<- *memberlist.Packet,
	reg prometheus.Registerer,
	log *log.Logger,
	localAddr string,
) *ConnPool {
	closing := make(chan string)

	p := &ConnPool{
		pool:      lru.New(5),
		closing:   closing,
		packetCh:  packetCh,
		logger:    log,
		localAddr: localAddr,
	}

	p.pool.OnEvicted = func(key lru.Key, conn interface{}) {
		conn.(*Conn).CloseInABit()
		p.logger.Printf("going to remove connection from pool")

		p.connRemovedFromPool.Inc()
	}

	p.registerMetrics(reg)

	return p
}

// TODO: Rework metric descriptions.
func (p *ConnPool) registerMetrics(reg prometheus.Registerer) {
	p.connAddedToPool = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "memberlist_tls_transport_conn_added_to_pool",
		Help: "Amount of connections added to connection pool.",
	})

	p.connRemovedFromPool = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "memberlist_tls_transport_conn_removed_from_pool",
		Help: "Amount of connections removed from connection pool",
	})

	reg.MustRegister(p.connAddedToPool, p.connRemovedFromPool)
}

// AddAndRead adds a connection to the pool and start reading for incoming
// packages.
func (p *ConnPool) AddAndRead(remoteAddr string, conn net.Conn, incoming bool) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	newConn, err := NewConn(
		remoteAddr,
		conn,
		p.packetCh,
		p.closing,
		p.logger,
		incoming,
	)
	if err != nil {
		return err
	}

	oldConn, oldExists := p.pool.Get(remoteAddr)

	if !oldExists {
		// No connection so far, adding new one.
		p.pool.Add(remoteAddr, newConn)
		p.connAddedToPool.Inc()
		return nil
	}

	if newConn.IsIncoming() == oldConn.(*Conn).IsIncoming() {
		// Both are incoming or outgoing, closing new one.
		newConn.CloseInABit()
		return nil
	}

	// If both A and B instantiate a connection at the same time, have A close
	// its incoming connection and B close its outgoing connection.
	if p.localAddr < remoteAddr {
		if newConn.IsIncoming() {
			// A: closing incoming new connection.
			newConn.CloseInABit()
			return nil
		}

		// A: closing incoming old connection.
		p.pool.Remove(remoteAddr)
		p.pool.Add(remoteAddr, newConn)
		p.connAddedToPool.Inc()
		return nil
	}

	if newConn.IsIncoming() {
		// B: closing outgoing old connection.
		p.pool.Remove(remoteAddr)
		p.pool.Add(remoteAddr, newConn)
		p.connAddedToPool.Inc()
		return nil
	}

	// B: closing outgoing new connection.
	newConn.CloseInABit()
	return nil
}

func (p *ConnPool) Get(addr string) (net.Conn, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()

	conn, ok := p.pool.Get(addr)
	if !ok {
		return nil, ok
	}
	return conn.(*Conn).conn, ok
}

func (p *ConnPool) gc() {
	for {
		addr := <-p.closing

		p.lock.Lock()
		defer p.lock.Unlock()

		p.pool.Remove(addr)
	}
}

func (p *ConnPool) Shutdown() {
	p.pool.Clear()
}
