// Tools for binary-encoding Crypto Conditions
package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Regex for validating fulfillments
//
// This is a generic, future-proof version of the fulfillment regular
// expression.
const FULFILLMENT_REGEX = "/^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$/"

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

func GetUvarint(b []byte) (uint64, []byte, error) {
	uv, offset := binary.Uvarint(b)
	if offset <= 0 {
		return 0, []byte{}, errors.New("error parsing Uvarint")
	}

	b = b[offset:]

	return uv, b, nil
}

func GetVarbyte(b []byte) ([]byte, []byte, error) {
	length, offset := binary.Uvarint(b)
	if offset <= 0 {
		return []byte{}, []byte{}, errors.New("error parsing Uvarint")
	}

	if !(uint64(len(b)) > length) {
		return nil, nil, errors.New("error parsing Varbyte")
	}
	vb, b := b[offset:][:length], b[offset:][length:]

	return vb, b, nil
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
