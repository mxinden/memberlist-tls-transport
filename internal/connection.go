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
}

func NewConn(
	remoteAddr string,
	c net.Conn,
	packetCh chan<- *memberlist.Packet,
	closing chan<- string,
	logger *log.Logger,
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

		c.logger.Println("reading ...")

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

		c.logger.Printf("Got msg from %v", c.remoteAddr)

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

// Add connection to pool and start reading for incoming packages.
// TODO: Check if the connection already exists, if so, the callback
// is not called when overwriting the value.
//
// TODO: If two instances instantiate a connection to each other at the same
// time, both of them might close the incoming connection at the same time,
// resulting in both of them being closed.
func (p *ConnPool) AddAndRead(remoteAddr string, conn net.Conn) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	newConn, err := NewConn(remoteAddr, conn, p.packetCh, p.closing, p.logger)
	if err != nil {
		return err
	}

	if _, ok := p.pool.Get(remoteAddr); ok {
		p.logger.Println("duplicate connection")
		if p.localAddr < remoteAddr {
			p.logger.Printf("closing new one: %v -> %v", p.localAddr, remoteAddr)
			newConn.CloseInABit()
			return nil
		}

		p.logger.Printf("closing old one: %v -> %v", p.localAddr, remoteAddr)
		p.pool.Remove(remoteAddr)
	}

	p.logger.Printf("Adding connection for %v", remoteAddr)
	p.pool.Add(remoteAddr, newConn)

	p.connAddedToPool.Inc()

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
