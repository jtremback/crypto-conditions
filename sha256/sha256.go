// Generates and parses Sha256 Crypto Conditions
package Sha256

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/jtremback/crypto-conditions/encoding"
)

type Fulfillment struct {
	Preimage             []byte
	MaxFulfillmentLength uint64
}

// Serializes to the Crypto Conditions string format. Discards the MaxFulfillmentLength.
func (ful Fulfillment) Serialize() string {
	return "cf:1:1:" + base64.URLEncoding.EncodeToString(ful.Preimage)
}

// Parses Fulfillment out of the Crypto Conditions string format, and checks it for validity.
func ParseFulfillment(s string) (*Fulfillment, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return nil, errors.New("parsing error")
	}

	if parts[0] != "cf" {
		return nil, errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return nil, errors.New("must be protocol version 1")
	}

	if parts[2] != "1" {
		return nil, errors.New("not an Sha256 condition")
	}

	// Get Preimage
	pre, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("parsing error")
	}

	ful := &Fulfillment{
		Preimage: pre,
	}

	return ful, nil
}

// Turns an in-memory Fulfillment to an in-memory Condition. If the MaxFulfillmentLength is
// not set on the Fulfillment, it will be set to the Fulfillment's serialized length.
func (ful Fulfillment) Condition() Condition {
	var length uint64

	if ful.MaxFulfillmentLength == 0 {
		length = uint64(len(ful.Serialize()))
	} else {
		length = ful.MaxFulfillmentLength
	}

	hash := sha256.Sum256(bytes.Join([][]byte{
		encoding.MakeVarbyte(ful.Preimage),
	}, []byte{}))

	return Condition{
		Hash:                 hash,
		MaxFulfillmentLength: length,
	}
}

type Condition struct {
	Hash                 [32]byte
	MaxFulfillmentLength uint64
}

// Serializes to the Crypto Conditions string format.
func (cond Condition) Serialize() string {
	return "cc:1:1:" + base64.URLEncoding.EncodeToString(cond.Hash[:]) + ":" + strconv.FormatUint(cond.MaxFulfillmentLength, 10)
}
