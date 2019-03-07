package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/require"
)

func TestJoin(t *testing.T) {
	_, cleanupFunc := createTwoMemberCluster(t)

	defer cleanupFunc()
}

func TestReusePacketTCPConnections(t *testing.T) {
	cluster, cleanupFunc := createTwoMemberCluster(t)

	defer cleanupFunc()

	metricFamilies, err := cluster.registries[1].Gather()
	if err != nil {
		t.Fatalf("failed to get metric families: %v", err)
	}

	for _, f := range metricFamilies {
		if *f.Name == "memberlist_tls_transport_conn_established" {
			require.Equal(
				t,
				float64(2),
				f.GetMetric()[0].GetCounter().GetValue(),
				"unexpected amount of established connections",
			)
			return
		}
	}

	t.Fatal("could not find metric")
}

type delegate struct {
	Msgs [][]byte
}

func (d *delegate) NodeMeta(limit int) []byte {
	return []byte{}
}

func (d *delegate) NotifyMsg(m []byte) {
	d.Msgs = append(d.Msgs, m)
}

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return [][]byte{}
}

func (d *delegate) LocalState(join bool) []byte {
	return []byte{}
}

func (d *delegate) MergeRemoteState(buf []byte, join bool) {
}

func TestSendBestEffort(t *testing.T) {
	cluster, cleanupFunc := createTwoMemberCluster(t)

	defer cleanupFunc()

	msg := "test123"

	// TODO: Make sure we are not sending to ourself
	err := cluster.members[0].SendBestEffort(cluster.members[1].Members()[1], []byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if len(cluster.delegates[1].Msgs) != 1 {
		t.Fatalf("expected delegate2 to have one messsage but got: %v", len(cluster.delegates[1].Msgs))
	}
}

func TestSendReliable(t *testing.T) {
	cluster, cleanupFunc := createTwoMemberCluster(t)

	defer cleanupFunc()

	msg := "test123"

	// TODO: Make sure we are not sending to ourself
	err := cluster.members[0].SendReliable(cluster.members[1].Members()[1], []byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if len(cluster.delegates[1].Msgs) != 1 {
		t.Fatalf("expected delegate2 to have one messsage but got: %v", len(cluster.delegates[1].Msgs))
	}
}

func TestRegistersMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	_, err := createMemberlist("1", nil, reg)
	if err != nil {
		panic("failed to create memberlist")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, 3, len(families), "unexpected length of metric families")
}

type twoMemberCluster struct {
	registries [2]*prometheus.Registry
	members    [2]*memberlist.Memberlist
	delegates  [2]*delegate
}

func createTwoMemberCluster(t *testing.T) (*twoMemberCluster, func()) {
	var err error

	c := &twoMemberCluster{
		registries: [2]*prometheus.Registry{},
		members:    [2]*memberlist.Memberlist{},
		delegates:  [2]*delegate{},
	}

	for i := 0; i < 2; i++ {
		c.registries[i] = prometheus.NewRegistry()

		c.delegates[i] = &delegate{}

		c.members[i], err = createMemberlist(strconv.Itoa(i), c.delegates[i], c.registries[i])
		if err != nil {
			t.Fatalf("failed to create memberlist %v: %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		_, err = c.members[i].Join([]string{c.members[(i+1)%2].LocalNode().Address()})
		if err != nil {
			panic("failed to join cluster")
		}
	}

	time.Sleep(time.Second)

	for i := 0; i < 2; i++ {
		if len(c.members[i].Members()) != 2 {
			t.Errorf("expected memberlist to have 2 members but got %v instead", len(c.members[i].Members()))
		}
	}

	cleanupFunc := func() {
		for i := 0; i < 2; i++ {
			err = c.members[i].Shutdown()
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	return c, cleanupFunc
}

func createMemberlist(id string, d memberlist.Delegate, reg prometheus.Registerer) (*memberlist.Memberlist, error) {
	nodeName := "node" + id

	// Generated via https://github.com/wolfeidau/golang-massl
	caCert, err := ioutil.ReadFile("./certs/ca.pem")
	if err != nil {
		log.Fatalf("failed to load cert: %s", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair("./certs/"+nodeName+".pem", "./certs/"+nodeName+"-key.pem")
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // server certificate which is validated by the client
		ClientCAs:    caCertPool,                     // used to verify the client cert is signed by the CA and is therefore valid
		ClientAuth:   tls.RequireAndVerifyClientCert, // this requires a valid client certificate to be supplied during handshake
		RootCAs:      caCertPool,                     // this is used to validate the server certificate
	}
	tlsConfig.BuildNameToCertificate()

	conf := memberlist.DefaultLocalConfig()
	// Let OS choose port so parallel unit tests don't conflict.
	conf.BindPort = 0

	if d != nil {
		conf.Delegate = d
	}

	conf.BindAddr = "127.0.0.1"
	conf.Logger = log.New(os.Stderr, id+": ", log.LstdFlags)

	nc := TLSTransportConfig{
		BindAddrs: []string{conf.BindAddr},
		BindPort:  conf.BindPort,
		// TODO: insert proper logger.
		Logger: conf.Logger,
		TLS:    tlsConfig,
	}

	// See comment below for details about the retry in here.
	makeNetRetry := func(limit int) (*TLSTransport, error) {
		var err error
		for try := 0; try < limit; try++ {
			var nt *TLSTransport
			if nt, err = NewTLSTransport(&nc, reg); err == nil {
				return nt, nil
			}
			if strings.Contains(err.Error(), "address already in use") {
				conf.Logger.Printf("[DEBUG] memberlist: Got bind error: %v", err)
				continue
			}
		}

		return nil, fmt.Errorf("failed to obtain an address: %v", err)
	}

	// The dynamic bind port operation is inherently racy because
	// even though we are using the kernel to find a port for us, we
	// are attempting to bind multiple protocols (and potentially
	// multiple addresses) with the same port number. We build in a
	// few retries here since this often gets transient errors in
	// busy unit tests.
	limit := 1
	if conf.BindPort == 0 {
		limit = 10
	}

	fmt.Println("limit: ", limit)

	nt, err := makeNetRetry(limit)
	if err != nil {
		panic(fmt.Sprintf("Could not set up network transport: %v", err))
	}
	if conf.BindPort == 0 {
		port := nt.GetAutoBindPort()
		conf.BindPort = port
		conf.AdvertisePort = port
		conf.Logger.Printf("[DEBUG] memberlist: Using dynamic bind port %d", port)
	}
	conf.Transport = nt

	conf.Name = fmt.Sprintf("cluster-%v", conf.BindPort)

	return memberlist.Create(conf)
}

func printMetricOnTestFailure(t *testing.T, r *prometheus.Registry) {
	fmt.Println("printMetricOnTestFailure")
	// 	if !t.Failed() {
	// 		return
	// 	}
	ms, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range ms {
		_, err = expfmt.MetricFamilyToText(os.Stdout, m)
		if err != nil {
			t.Fatal(err)
		}
	}
}
