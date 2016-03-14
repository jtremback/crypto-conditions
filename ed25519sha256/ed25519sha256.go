// Generates and parses Ed25519-Sha256 Crypto Conditions
package Ed25519Sha256

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/agl/ed25519"
	"github.com/jtremback/crypto-conditions/encoding"
)

func sliceTo64Byte(slice []byte) *[64]byte {
	if len(slice) == 64 {
		var array [64]byte
		copy(array[:], slice[:64])
		return &array
	}
	return &[64]byte{}
}

func sliceTo32Byte(slice []byte) *[32]byte {
	if len(slice) == 32 {
		var array [32]byte
		copy(array[:], slice[:32])
		return &array
	}
	return &[32]byte{}
}

type Fulfillment struct {
	PublicKey    []byte
	MessageId    []byte
	FixedMessage []byte
	// MaxDynamicMessageLength uint64
	DynamicMessage       []byte
	Signature            []byte
	MaxFulfillmentLength uint64
}

// Serializes to the Crypto Conditions Fulfillment string format. Unlike Sha256 Fulfillments,
// it has a MaxFulfillmentLength
func (ful Fulfillment) Serialize(privkey []byte) string {
	payload := base64.URLEncoding.EncodeToString(bytes.Join([][]byte{
		encoding.MakeVarbyte(ful.PublicKey),
		encoding.MakeVarbyte(ful.MessageId),
		encoding.MakeVarbyte(ful.FixedMessage),
		// encoding.MakeVaruint(ful.MaxDynamicMessageLength),
		encoding.MakeVarbyte(ful.DynamicMessage),
		encoding.MakeVarbyte(ed25519.Sign(sliceTo64Byte(privkey), append(ful.FixedMessage, ful.DynamicMessage...))[:]),
	}, []byte{}))

	return "cf:1:8:" + payload + ":" + strconv.FormatUint(ful.MaxFulfillmentLength, 10)
}

// Parses Fulfillment out of the Crypto Conditions string format,
// and checks it for validity, including the signature.
func ParseFulfillment(s string) (*Fulfillment, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 5 {
		return nil, errors.New("parsing error")
	}

	if parts[0] != "cf" {
		return nil, errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return nil, errors.New("must be protocol version 1")
	}

	if parts[2] != "8" {
		return nil, errors.New("not an Ed25519Sha256 condition")
	}

	b, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("parsing error")
	}

	pubkey, b := encoding.GetVarbyte(b)

	messageId, b := encoding.GetVarbyte(b)

	fixedMessage, b := encoding.GetVarbyte(b)

	// // Get MaxDynamicMessageLength
	// maxDynamicMessageLength, offset := binary.Uvarint(b)
	// b = b[:offset:]

	dynamicMessage, b := encoding.GetVarbyte(b)

	signature, b := encoding.GetVarbyte(b)

	// Check signature
	fullMessage := append(fixedMessage, dynamicMessage...)
	if !ed25519.Verify(sliceTo32Byte(pubkey), fullMessage, sliceTo64Byte(signature)) {
		return nil, errors.New("signature not valid")
	}

	// Get MaxFulfillmentLength
	maxFulfillmentLength, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return nil, errors.New("invalid maxFulfillmentLength")
	}

	ful := &Fulfillment{
		PublicKey:    pubkey,
		MessageId:    messageId,
		FixedMessage: fixedMessage,
		// MaxDynamicMessageLength: maxDynamicMessageLength,
		DynamicMessage:       dynamicMessage,
		Signature:            signature,
		MaxFulfillmentLength: maxFulfillmentLength,
	}

	return ful, nil
}

// Turns an in-memory Fulfillment to an in-memory Condition. DynamicMessage and Signature
// are discarded if present.
func (ful Fulfillment) Condition() string {
	hash := sha256.Sum256(bytes.Join([][]byte{
		encoding.MakeVarbyte(ful.PublicKey),
		encoding.MakeVarbyte(ful.MessageId),
		encoding.MakeVarbyte(ful.FixedMessage),
	}, []byte{}))

	return "cc:1:8:" + base64.URLEncoding.EncodeToString(hash[:]) + ":" + strconv.FormatUint(ful.MaxFulfillmentLength, 10)
}

type Condition struct {
	PublicKey            []byte
	MessageId            []byte
	FixedMessage         []byte
	MaxFulfillmentLength uint64
}

// Serializes to the Crypto Conditions string format.
func (cond Condition) Serialize() string {
	hash := sha256.Sum256(bytes.Join([][]byte{
		encoding.MakeVarbyte(cond.PublicKey),
		encoding.MakeVarbyte(cond.MessageId),
		encoding.MakeVarbyte(cond.FixedMessage),
	}, []byte{}))

	return "cc:1:8:" + base64.URLEncoding.EncodeToString(hash[:]) + ":" + strconv.FormatUint(cond.MaxFulfillmentLength, 10)
}
