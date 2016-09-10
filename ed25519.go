package CryptoConditions

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/agl/ed25519"
)

type Condition struct {
	Type                 uint16
	FeatureBitmask       []byte
	Fingerprint          []byte
	MaxFulfillmentLength uint64
}

type Ed25519Fulfillment struct {
	PublicKey [32]byte
	Signature [64]byte
}

func ParseEd25519Fulfillment(payload []byte) (Ed25519Fulfillment, error) {
	buf := bytes.NewReader(payload)
	ful := Ed25519Fulfillment{}
	err := binary.Read(buf, binary.LittleEndian, ful)
	return ful, err
}

func Ed25519Validate(payload []byte, message []byte) error {
	ful, err := ParseEd25519Fulfillment(payload)
	if err != nil {
		return err
	}

	if !ed25519.Verify(&ful.PublicKey, message, &ful.Signature) {
		return errors.New("signature not valid")
	}

	return nil
}

func (ful *Ed25519Fulfillment) Condition() Condition {
	return Condition{
		Type:                 4,
		FeatureBitmask:       []byte{0x20},
		Fingerprint:          ful.PublicKey[:],
		MaxFulfillmentLength: 96,
	}
}
