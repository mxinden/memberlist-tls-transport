package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/memberlist"
	"github.com/mxinden/tls_memberlist/internal"
)

func main() {
	conf := memberlist.DefaultLocalConfig()

	nc := &internal.NetTransportConfig{
		BindAddrs: []string{conf.BindAddr},
		BindPort:  conf.BindPort,
		// TODO: insert proper logger.
		Logger: &log.Logger{},
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

	list, err := memberlist.Create(conf)
	if err != nil {
		panic("failed to create memberlist")
	}

	for _, m := range list.Members() {
		fmt.Printf("Member: %s %s\n", m.Name, m.Addr)
	}
}
