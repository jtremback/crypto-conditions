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

func sliceTo64Byte(slice []byte) [64]byte {
	if len(slice) == 64 {
		var array [64]byte
		copy(array[:], slice[:64])
		return array
	}
	return [64]byte{}
}

func sliceTo32Byte(slice []byte) [32]byte {
	if len(slice) == 32 {
		var array [32]byte
		copy(array[:], slice[:32])
		return array
	}
	return [32]byte{}
}

type Fulfillment struct {
	PublicKey               [32]byte
	MessageId               []byte
	FixedMessage            []byte
	MaxDynamicMessageLength uint64
	DynamicMessage          []byte
	Signature               [64]byte
}

// Serializes to the Crypto Conditions Fulfillment string format.
func (ful *Fulfillment) Serialize() string {
	payload := base64.URLEncoding.EncodeToString(bytes.Join([][]byte{
		encoding.MakeVarbyte(ful.PublicKey[:]),
		encoding.MakeVarbyte(ful.MessageId),
		encoding.MakeVarbyte(ful.FixedMessage),
		encoding.MakeUvarint(ful.MaxDynamicMessageLength),
		encoding.MakeVarbyte(ful.DynamicMessage),
		encoding.MakeVarbyte(ful.Signature[:]),
	}, []byte{}))

	return "cf:1:8:" + payload
}

// Signs an in-memory Fulfillment
func (ful *Fulfillment) Sign(privkey [64]byte) {
	ful.Signature = *ed25519.Sign(&privkey, append(ful.FixedMessage, ful.DynamicMessage...))
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

	pk, b := encoding.GetVarbyte(b)
	pubkey := sliceTo32Byte(pk)
	messageId, b := encoding.GetVarbyte(b)
	fixedMessage, b := encoding.GetVarbyte(b)
	maxDynamicMessageLength, b := encoding.GetUvarint(b)
	dynamicMessage, b := encoding.GetVarbyte(b)
	sig, b := encoding.GetVarbyte(b)
	signature := sliceTo64Byte(sig)

	// Check signature
	fullMessage := append(fixedMessage, dynamicMessage...)
	if !ed25519.Verify(&pubkey, fullMessage, &signature) {
		return nil, errors.New("signature not valid")
	}

	ful := &Fulfillment{
		PublicKey:               pubkey,
		MessageId:               messageId,
		FixedMessage:            fixedMessage,
		MaxDynamicMessageLength: maxDynamicMessageLength,
		DynamicMessage:          dynamicMessage,
		Signature:               signature,
	}

	return ful, nil
}

// Turns an in-memory Fulfillment to an in-memory Condition. DynamicMessage and Signature
// are discarded if present.
func (ful *Fulfillment) Condition() Condition {
	var length uint64

	if ful.MaxDynamicMessageLength == 0 {
		length = uint64(len(ful.Serialize()))
	} else {
		length = ful.MaxDynamicMessageLength
	}

	return Condition{
		PublicKey:               ful.PublicKey,
		MessageId:               ful.MessageId,
		FixedMessage:            ful.FixedMessage,
		MaxDynamicMessageLength: length,
	}
}

type Condition struct {
	PublicKey               [32]byte
	MessageId               []byte
	FixedMessage            []byte
	MaxDynamicMessageLength uint64
}

// Serializes to the Crypto Conditions string format.
func (cond *Condition) Serialize() string {
	hash := sha256.Sum256(bytes.Join([][]byte{
		encoding.MakeVarbyte(cond.PublicKey[:]),
		encoding.MakeVarbyte(cond.MessageId),
		encoding.MakeVarbyte(cond.FixedMessage),
	}, []byte{}))

	return "cc:1:8:" + base64.URLEncoding.EncodeToString(hash[:]) + ":" + strconv.FormatUint(cond.MaxDynamicMessageLength, 10)
}

func FulfillmentToCondition(s string) (string, error) {
	ful, err := ParseFulfillment(s)
	if err != nil {
		return "", err
	}

	cond := ful.Condition()

	condString := cond.Serialize()
	return condString, nil
}
