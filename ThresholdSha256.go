package CryptoConditions

import (
	"encoding/binary"
	"errors"

	"github.com/jtremback/crypto-conditions/encoding"
)

type WeightedString struct {
	Weight uint32
	String []byte
}

type WeightedStrings []WeightedString

func ParseWeightedStrings(b []byte) (WeightedStrings, error) {
	bs := encoding.ParseVarray(b)
	ws := WeightedStrings{}

	for _, b := range bs {
		w, b, err := encoding.GetUvarint(b)
		if err != nil {
			return nil, err
		}

		s, _, err := encoding.GetVarbyte(b)
		if err != nil {
			return nil, err
		}

		ws = append(ws, WeightedString{
			Weight: uint32(w),
			String: s,
		})
	}

	return ws, nil
}

func (a WeightedStrings) Len() int      { return len(a) }
func (a WeightedStrings) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a WeightedStrings) Less(i, j int) bool {
	// Sort lexicographically if the lengths are equal
	if len(a[i].String) == len(a[j].String) {
		return string(a[i].String) < string(a[j].String)
	}

	// Sort by length otherwise
	return len(a[i].String) < len(a[j].String)
}

func (wss *WeightedStrings) WriteTo(b []byte) {
	i := 0
	for _, ws := range *wss {
		// write weight
		i = binary.PutUvarint(b[i:], uint64(ws.Weight))
		// prefix length
		i = binary.PutUvarint(b[i:], uint64(len(ws.String)))
		// write fulfillment or condition
		b = append(b[i:], ws.String...)
	}
}

func ParseFulfillment(b []byte) (uint16, []byte, error) {
	typ, b, err := encoding.GetUvarint(b)
	if err != nil {
		return 0, []byte{}, err
	}

	payload, b, err := encoding.GetVarbyte(b)
	if err != nil {
		return 0, []byte{}, err
	}

	return uint16(typ), payload, nil
}

type ThresholdSha256Fulfillment struct {
	Threshold       uint32
	SubFulfillments WeightedStrings
}

func ParseThresholdSha256Fulfillment(payload []byte) (*ThresholdSha256Fulfillment, error) {
	threshold, b, err := encoding.GetUvarint(payload)
	if err != nil {
		return nil, err
	}

	f, b, err := encoding.GetVarbyte(b)
	if err != nil {
		return nil, err
	}

	subFulfillments, err := ParseWeightedStrings(f)
	if err != nil {
		return nil, err
	}

	ful := &ThresholdSha256Fulfillment{
		Threshold:       uint32(threshold),
		SubFulfillments: subFulfillments,
	}

	return ful, nil
}

func (ful *ThresholdSha256Fulfillment) Serialize() []byte {
	b := []byte{}

	// write threshold
	i := binary.PutUvarint(b, uint64(ful.Threshold))

	// write subfulfillments
	ful.SubFulfillments.WriteTo(b[i:])

	return b
}

func Validate(fulfillment []byte, message []byte) error {
	typ, payload, err := ParseFulfillment(fulfillment)
	if err != nil {
		return err
	}
	switch typ {
	case 2:
		err := ThresholdSha256Validate(payload, message)
		if err != nil {
			return err
		}
		return nil
	case 4:
		err := Ed25519Validate(payload, message)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("Unrecognized fulfillment type")
	}
}

func ThresholdSha256Validate(payload []byte, message []byte) error {
	ful, err := ParseThresholdSha256Fulfillment(payload)
	if err != nil {
		return err
	}

	var fulfilled uint32

	for _, sf := range ful.SubFulfillments {
		err := Validate(sf.String, message)
		if err != nil {
			return err
		}
		fulfilled += sf.Weight
	}

	if fulfilled < ful.Threshold {
		return errors.New("Not enough fulfillments")
	}

	return nil
}

func (ful *ThresholdSha256Fulfillment) Condition() Condition {
	subconditions := make(WeightedStrings, len(ful.SubFulfillments))
	for i, sf := range ful.SubFulfillments {
		subconditions[i] = WeightedString{
			Weight: sf.Weight,
			String: sf.String,
		}
	}

	// Still need to sort

	return Condition{
		Type:           2,
		FeatureBitmask: []byte{0x09},
		// Fingerprint:          sha256.Sum256()[:],
		MaxFulfillmentLength: 96,
	}
}
