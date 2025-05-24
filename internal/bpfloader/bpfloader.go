package bpfloader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type SPAEvent struct {
	SrcIP   uint32
	SrcPort uint16
	_       [2]byte // padding for alignment
}

func LoadAndAttach(ifaceName string) (*ebpf.Collection, <-chan SPAEvent, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to set rlimit: %w", err)
	}

	// Load pre-compiled BPF object file
	spec, err := ebpf.LoadCollectionSpec("bpf/spa_xdp.o")
	if err != nil {
		return nil, nil, fmt.Errorf("loading collection spec: %w", err)
	}

	// Load into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("loading collection into kernel: %w", err)
	}

	prog := coll.Programs["xdp_spa_filter"]
	if prog == nil {
		return nil, nil, fmt.Errorf("program xdp_spa_filter not found")
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Attach XDP program to interface
	_, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attaching XDP program: %w", err)
	}

	// Open ring buffer reader for events map
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	events := make(chan SPAEvent)

	go func() {
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("ringbuf read error: %v", err)
				continue
			}

			var event SPAEvent
			buf := bytes.NewReader(record.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %v", err)
				continue
			}

			events <- event
		}
	}()

	return coll, events, nil
}
