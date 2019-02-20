package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/mxinden/tls_memberlist/internal"
)

func TestJoin(t *testing.T) {
	list1, err := createMemberlist(9000, nil)
	if err != nil {
		panic("failed to create memberlist")
	}

	list2, err := createMemberlist(9001, nil)
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{"127.0.0.1:9001"})
	if err != nil {
		panic("failed to join cluster")
	}

	_, err = list2.Join([]string{"127.0.0.1:9000"})
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
	list1, err := createMemberlist(9000, &delegate1)
	if err != nil {
		panic("failed to create memberlist")
	}

	delegate2 := delegate{}
	list2, err := createMemberlist(9001, &delegate2)
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{"127.0.0.1:9001"})
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
	list1, err := createMemberlist(9000, &delegate1)
	if err != nil {
		panic("failed to create memberlist")
	}

	delegate2 := delegate{}
	list2, err := createMemberlist(9001, &delegate2)
	if err != nil {
		panic("failed to create memberlist")
	}

	_, err = list1.Join([]string{"127.0.0.1:9001"})
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

func createMemberlist(port int, d memberlist.Delegate) (*memberlist.Memberlist, error) {
	conf := memberlist.DefaultLocalConfig()
	conf.UDPBufferSize = 1

	if d != nil {
		conf.Delegate = d
	}

	conf.Name = fmt.Sprintf("cluster-%v", port)

	conf.BindPort = port
	conf.BindAddr = "127.0.0.1"
	conf.Logger = log.New(os.Stderr, "", log.LstdFlags)

	// TODO: Should be tls transport config.
	nc := &internal.NetTransportConfig{
		BindAddrs: []string{conf.BindAddr},
		BindPort:  conf.BindPort,
		// TODO: insert proper logger.
		Logger: conf.Logger,
	}

	// See comment below for details about the retry in here.
	makeNetRetry := func(limit int) (*internal.NetTransport, error) {
		var err error
		for try := 0; try < limit; try++ {
			var nt *internal.NetTransport
			if nt, err = internal.NewNetTransport(nc); err == nil {
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

	return memberlist.Create(conf)
}
