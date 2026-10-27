package request

import (
	"crypto/sha256"
	"encoding/binary"
)

const digestPrefix = "nyyrikki-request-v1\x00"

// Digest is what an approval binds to (docs/04 §5.3): SHA-256 over the
// prefix, the target, the canonical argv and stdin. The argv is encoded as
// its element count and then each element with its length, both 8-byte
// big-endian, so no two requests share an encoding: without the count, the
// boundary between the last element and stdin would be ambiguous. Target
// names are slugs (docs/02 D5), so the NUL after the target is unambiguous.
// The interactive bit is not part of it: the runner compares it with the
// Grant separately.
func Digest(target string, c *Canonical) [32]byte {
	h := sha256.New()
	h.Write([]byte(digestPrefix))
	h.Write([]byte(target))
	h.Write([]byte{0})
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(c.argv)))
	h.Write(n[:])
	for _, a := range c.argv {
		binary.BigEndian.PutUint64(n[:], uint64(len(a)))
		h.Write(n[:])
		h.Write([]byte(a))
	}
	h.Write([]byte{0})
	h.Write(c.stdin)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}
