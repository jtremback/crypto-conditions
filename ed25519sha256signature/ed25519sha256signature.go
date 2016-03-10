package Ed25519Sha256Signatue

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/agl/ed25519"
)

type Parameters struct {
	MessageId               []byte
	FixedMessage            []byte
	MaxDynamicMessageLength uint64
	DynamicMessage          []byte
}

func MakeFulfillment(pubkey []byte, privkey [64]byte, param Parameters) string {
	payload := base64.URLEncoding.EncodeToString(bytes.Join([][]byte{
		makeVarbyte(param.MessageId),
		makeVarbyte(param.FixedMessage),
		makeVaruint(param.MaxDynamicMessageLength),
		makeVarbyte(param.DynamicMessage),
		makeVarbyte(ed25519.Sign(&privkey, append(self.FixedMessage, self.DynamicMessage...))[:]),
	}, []byte{}))

	return "cf:1:8:" + payload
}

func ConditionFromFulfillment(ful string) (string, error) {
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
