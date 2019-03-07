package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/require"
)

func TestJoin(t *testing.T) {
	registry1 := prometheus.NewRegistry()
	defer printMetricOnTestFailure(t, registry1)
	list1, err := createMemberlist("1", nil, registry1)
	if err != nil {
		panic("failed to create memberlist")
	}

	registry2 := prometheus.NewRegistry()
	defer printMetricOnTestFailure(t, registry2)
	list2, err := createMemberlist("2", nil, registry2)
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{list2.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	time.Sleep(time.Second)

	_, err = list2.Join([]string{list1.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	time.Sleep(2 * time.Second)

	if len(list1.Members()) != 2 || len(list2.Members()) != 2 {
		t.Errorf("expected each memberlist to have 2 members but got %v and %v instead", len(list1.Members()), len(list2.Members()))

		t.Error("List 1:")
		for _, m := range list1.Members() {
			t.Errorf("Member: %s %s\n", m.Name, m.Addr)
		}

		t.Error("List 2:")
		for _, m := range list2.Members() {
			t.Errorf("Member: %s %s\n", m.Name, m.Addr)
		}
	}

	err = list1.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
	err = list2.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReusePacketTCPConnections(t *testing.T) {
	list1Registry := prometheus.NewRegistry()
	defer printMetricOnTestFailure(t, list1Registry)
	list1, err := createMemberlist("1", nil, list1Registry)
	if err != nil {
		panic("failed to create memberlist")
	}

	list2, err := createMemberlist("2", nil, prometheus.NewRegistry())
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{list2.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	_, err = list2.Join([]string{list1.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	time.Sleep(1 * time.Second)

	if len(list1.Members()) != 2 || len(list2.Members()) != 2 {
		t.Errorf("expected each memberlist to have 2 members but got %v and %v instead", len(list1.Members()), len(list2.Members()))

		t.Error("List 1:")
		for _, m := range list1.Members() {
			t.Errorf("Member: %s %s\n", m.Name, m.Addr)
		}

		t.Error("List 2:")
		for _, m := range list2.Members() {
			t.Errorf("Member: %s %s\n", m.Name, m.Addr)
		}
	}

	err = list1.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
	err = list2.Shutdown()
	if err != nil {
		t.Fatal(err)
	}

	metricFamilies, err := list1Registry.Gather()
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
	msg := "test123"
	delegate1 := delegate{}
	list1, err := createMemberlist("1", &delegate1, prometheus.NewRegistry())
	if err != nil {
		panic("failed to create memberlist")
	}

	delegate2 := delegate{}
	list2, err := createMemberlist("2", &delegate2, prometheus.NewRegistry())
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{list2.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	_, err = list2.Join([]string{list1.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	// TODO: Make sure we are not sending to ourself
	err = list1.SendBestEffort(list2.Members()[1], []byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if len(delegate2.Msgs) != 1 {
		t.Fatalf("expected delegate2 to have one messsage but got: %v", len(delegate2.Msgs))
	}

	err = list1.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
	err = list2.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendReliable(t *testing.T) {
	msg := "test123"
	delegate1 := delegate{}
	list1, err := createMemberlist("1", &delegate1, prometheus.NewRegistry())
	if err != nil {
		panic("failed to create memberlist")
	}

	delegate2 := delegate{}
	list2, err := createMemberlist("2", &delegate2, prometheus.NewRegistry())
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{list2.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	_, err = list2.Join([]string{list1.LocalNode().Address()})
	if err != nil {
		panic("failed to join cluster")
	}

	// TODO: Make sure we are not sending to ourself
	err = list1.SendReliable(list2.Members()[1], []byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if len(delegate2.Msgs) != 1 {
		t.Fatalf("expected delegate2 to have one messsage but got: %v", len(delegate2.Msgs))
	}

	err = list1.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
	err = list2.Shutdown()
	if err != nil {
		t.Fatal(err)
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

func createMemberlist(id string, d memberlist.Delegate, reg prometheus.Registerer) (*memberlist.Memberlist, error) {
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
