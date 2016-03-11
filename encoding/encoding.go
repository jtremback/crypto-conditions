// Tools for binary-encoding Crypto Conditions
package encoding

import (
	"bytes"
	"encoding/binary"
)

// MakeUvarint returns a byte slice containing a uvarint
func MakeUvarint(n uint64) []byte {
	uvi := make([]byte, 10)
	i := binary.PutUvarint(uvi, n)
	return uvi[:i]
}

// MakeVarbyte prefixes a byte slice with its length
func MakeVarbyte(buf []byte) []byte {
	length := len(buf)
	b := bytes.Join([][]byte{MakeUvarint(uint64(length)), buf}, []byte{})

	return b
}

// MakeVarray takes a slice of byte slices and returns a byte slice
// containing a concatenated list of Varbytes
func MakeVarray(items [][]byte) []byte {
	b := [][]byte{}
	for _, buf := range items {
		b = append(b, MakeVarbyte(buf))
	}

	return bytes.Join(b, []byte{})
}

// ParseVarray takes a byte slice containing a concatenated list
// of Varbytes, and returns a slice of byte slices
func ParseVarray(b []byte) [][]byte {
	arr := [][]byte{}
	for len(b) > 0 {
		length, offset := binary.Uvarint(b)
		b = b[offset:]
		arr = append(arr, b[:length])
		b = b[length:]
	}

	return arr
}
