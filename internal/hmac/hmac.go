package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"os"
)

// Shared secret key (in a real system, load from secure config or env variable)
var secretKey []byte

func init() {
	key := os.Getenv("WARLOCK_SECRET")
	if key == "" {
		log.Fatal("WARLOCK_SECRET environment variable not set")
	}
	secretKey = []byte(key)
}

// SPAEvent matches the BPF event struct
type SPAEvent struct {
	SrcIP   uint32
	SrcPort uint16
	_       [2]byte // padding
}

// Validate checks if the event is authentic by verifying its HMAC signature.
// For this example, assume the signature is embedded in the UDP payload (not shown here).
// Since the eBPF program does not carry payload, this is a placeholder stub.
//
// You would extend the eBPF program to capture and pass the signature bytes along with the event,
// then verify HMAC over packet data using secretKey here.
func Validate(event SPAEvent) bool {
	// This is a simplified stub for demonstration:
	// You need actual payload and signature to validate HMAC.

	// For example, generate a message from SrcIP and SrcPort
	msg := make([]byte, 6)
	binary.BigEndian.PutUint32(msg[0:4], event.SrcIP)
	binary.BigEndian.PutUint16(msg[4:6], event.SrcPort)

	mac := hmac.New(sha256.New, secretKey)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)

	// Here, compare expectedMAC with actual MAC from packet (not implemented)
	// So we just return true for now, but **do NOT do this in production!**
	return true
}
