package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/mxinden/tls_memberlist/internal"
)

func main() {
	list1, err := createMemberlist(9000)
	if err != nil {
		panic("failed to create memberlist")
	}

	list2, err := createMemberlist(9001)
	if err != nil {
		panic("failed to create memberlist")
	}

	n, err := list1.Join([]string{"127.0.0.1:9001"})
	if err != nil {
		panic("failed to join cluster")
	}

	fmt.Printf("joined %v clusters", n)
	n, err = list2.Join([]string{"127.0.0.1:9000"})
	if err != nil {
		panic("failed to join cluster")
	}
	fmt.Printf("joined %v clusters", n)

	time.Sleep(time.Second * 30)

	for _, m := range list1.Members() {
		fmt.Printf("Member: %s %s\n", m.Name, m.Addr)
	}

	for _, m := range list2.Members() {
		fmt.Printf("Member: %s %s\n", m.Name, m.Addr)
	}
}

func createMemberlist(port int) (*memberlist.Memberlist, error) {
	conf := memberlist.DefaultLocalConfig()

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
