package netfilter

import (
	"encoding/binary"

	"github.com/vishvananda/netlink/nl"
)

// nlAttr is one netlink attribute: its type (flags masked off), payload,
// and the whole attribute including header and alignment padding, ready to
// be copied into another request.
type nlAttr struct {
	typ uint16
	val []byte
	raw []byte
}

// walkAttrs calls fn for every well-formed attribute in b and stops at the
// first malformed one. fn returns false to stop early.
func walkAttrs(b []byte, fn func(a nlAttr) bool) {
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return
		}
		end := (l + 3) &^ 3
		if end > len(b) {
			end = len(b)
		}
		a := nlAttr{
			typ: binary.NativeEndian.Uint16(b[2:4]) & nl.NLA_TYPE_MASK,
			val: b[4:l],
			raw: b[:end],
		}
		if !fn(a) {
			return
		}
		b = b[end:]
	}
}

// findAttr returns the first attribute of type typ in b.
func findAttr(b []byte, typ uint16) (nlAttr, bool) {
	var found nlAttr
	ok := false
	walkAttrs(b, func(a nlAttr) bool {
		if a.typ == typ {
			found, ok = a, true
			return false
		}
		return true
	})
	return found, ok
}

// appendAligned appends raw and pads it to the 4-byte netlink alignment.
func appendAligned(dst, raw []byte) []byte {
	dst = append(dst, raw...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}
