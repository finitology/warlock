package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
)

func main() {
    secret := []byte("changeme-super-secret") // Must match your warlock daemon
    message := []byte("unlock")               // Arbitrary message content

    mac := hmac.New(sha256.New, secret)
    mac.Write(message)
    signature := mac.Sum(nil)

    // Send to the interface's IP (replace with actual IP!)
    addr := net.UDPAddr{
        IP:   net.ParseIP("192.168.1.9"), // Replace with your actual IP on wlp0s20f3
        Port: 7000,
    }

    conn, err := net.DialUDP("udp", nil, &addr)
    if err != nil {
        fmt.Println("Dial failed:", err)
        os.Exit(1)
    }
    defer conn.Close()

    _, err = conn.Write(signature)
    if err != nil {
        fmt.Println("Write failed:", err)
        os.Exit(1)
    }

    fmt.Println("Sent SPA packet")
}
