package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Must match struct in spa_xdp.c
type spaEvent struct {
    SrcIP     uint32
    SrcPort   uint16
    Signature [32]byte
}

var sharedSecret = []byte("changeme-super-secret") // Replace with strong secret

func verifyHMAC(msg []byte, expected [32]byte) bool {
    mac := hmac.New(sha256.New, sharedSecret)
    mac.Write(msg)
    return hmac.Equal(mac.Sum(nil), expected[:])
}

func main() {

    var rlimit syscall.Rlimit
    err := syscall.Getrlimit(8, &rlimit) // 8 = RLIMIT_MEMLOCK on Linux
    if err != nil {
        log.Fatalf("Error getting memlock rlimit: %v", err)
    }
    fmt.Printf("Current memlock rlimit: cur=%d, max=%d\n", rlimit.Cur, rlimit.Max)

    // Optionally set to unlimited:
    rlimit.Cur = ^uint64(0)
    rlimit.Max = ^uint64(0)
    if err := syscall.Setrlimit(8, &rlimit); err != nil {
        log.Fatalf("Failed to set memlock rlimit: %v", err)
    }

    // Load compiled eBPF object file
    spec, err := ebpf.LoadCollectionSpec("bpf/spa_xdp.o")
    if err != nil {
        log.Fatalf("loading collection spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("loading collection: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["xdp_spa_filter"]
    if prog == nil {
        log.Fatal("xdp_spa_filter not found")
    }

    // Attach to interface (replace "eth0" with yours)
    ifaceName := "wlp0s20f3"
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        log.Fatalf("getting interface %s: %v", ifaceName, err)
    }

    lnk, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatalf("attaching XDP: %v", err)
    }
    defer lnk.Close()
    log.Printf("XDP program attached to %s", ifaceName)

    // Open ring buffer
    rb, err := ringbuf.NewReader(coll.Maps["events"])
    if err != nil {
        log.Fatalf("opening ringbuf: %v", err)
    }
    defer rb.Close()

    // Handle Ctrl+C
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    log.Println("Listening for SPA packets...")
loop:
    for {
        select {
        case <-sig:
            break loop
        default:
            record, err := rb.Read()
            if err != nil {
                continue
            }

            var event spaEvent
            err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
            if err != nil {
                log.Printf("binary read failed: %v", err)
                continue
            }

            ip := net.IPv4(byte(event.SrcIP), byte(event.SrcIP>>8), byte(event.SrcIP>>16), byte(event.SrcIP>>24))
            log.Printf("Received SPA packet from %s:%d", ip, event.SrcPort)

            dummyMsg := []byte("open sesame") // Should match content signed by sender
            if verifyHMAC(dummyMsg, event.Signature) {
                log.Println("✅ Valid HMAC! Opening port 8080")
                openFirewallPort(8080)
            } else {
                log.Println("❌ Invalid HMAC!")
            }
        }
    }
}

func openFirewallPort(port int) {
    cmd := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", fmt.Sprint(port), "-j", "ACCEPT")
    err := cmd.Run()
    if err != nil {
        log.Printf("failed to open firewall port: %v", err)
    }
}