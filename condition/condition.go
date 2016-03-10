package condition

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/agl/ed25519"
)

func makeVaruint(n uint64) []byte {
	uvi := make([]byte, 10)
	i := binary.PutUvarint(uvi, n)
	return uvi[:i]
}

func makeVarbyte(buf []byte) []byte {
	length := len(buf)
	b := bytes.Join([][]byte{makeVaruint(uint64(length)), buf}, []byte{})

	return b
}

func makeVarray(items [][]byte) []byte {
	b := [][]byte{}
	for _, buf := range items {
		b = append(b, makeVarbyte(buf))
	}

	return makeVarbyte(bytes.Join(b, []byte{}))
}

func parseVarray(b []byte) [][]byte {
	arr := [][]byte{}
	for len(b) > 0 {
		length, offset := binary.Uvarint(b)
		b = b[offset:]
		arr = append(arr, b[:length])
		b = b[length:]
	}

	return arr
}

type Sha256 struct {
}

func (self *Sha256) MakeFulfillment(pre []byte) string {
	return "cf:1:1:" + base64.URLEncoding.EncodeToString(pre)
}

func (self *Sha256) ConditionFromFulfillment(ful string) (string, error) {
	parts := strings.Split(ful, ":")

	if parts[0] != "cf" {
		return "", errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return "", errors.New("must be protocol version 1")
	}

	if parts[2] != "1" {
		return "", errors.New("not a Sha256 condition")
	}

	pre, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", errors.New("parsing error")
	}

	hash := sha256.Sum256(pre)
	b64 := base64.URLEncoding.EncodeToString(hash[:])
	length := fmt.Sprintf("%d", len(ful))

	return "cc:1:1:" + b64 + ":" + length, nil
}

type Ed25519Sha256 struct {
	MessageId               []byte
	FixedMessage            []byte
	MaxDynamicMessageLength uint64
	DynamicMessage          []byte
}

func (self Ed25519Sha256) MakeFulfillment(pubkey []byte, privkey [64]byte) string {
	payload := base64.URLEncoding.EncodeToString(bytes.Join([][]byte{
		makeVarbyte(self.MessageId),
		makeVarbyte(self.FixedMessage),
		makeVaruint(self.MaxDynamicMessageLength),
		makeVarbyte(self.DynamicMessage),
		makeVarbyte(ed25519.Sign(&privkey, append(self.FixedMessage, self.DynamicMessage...))[:]),
	}, []byte{}))

	return "cf:1:8:" + payload
}

func (self Ed25519Sha256) ConditionFromFulfillment(ful string) (string, error) {
	parts := strings.Split(ful, ":")

	if parts[0] != "cf" {
		return "", errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return "", errors.New("must be protocol version 1")
	}

	if parts[2] != "8" {
		return "", errors.New("not an Ed25519Sha256 condition")
	}

	b, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", errors.New("parsing error")
	}

	arr := []byte{}

	l, o := binary.Uvarint(b)
	arr, b = append(arr, b[o:][:l]...), b[o:][l:]

	l, o = binary.Uvarint(b)
	arr, b = append(arr, b[o:][:l]...), b[o:][l:]

	maxDynamicMessageLength, o := binary.Uvarint(b)
	arr = append(arr, b[:o]...)

	b64 := base64.URLEncoding.EncodeToString(arr)
	length := fmt.Sprintf("%d", uint64(len(arr))+maxDynamicMessageLength+64)

	return "cc:1:8:" + b64 + ":" + length, nil
}
