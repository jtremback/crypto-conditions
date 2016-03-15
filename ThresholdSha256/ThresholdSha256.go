// Generates and parses Ed25519-Sha256 Crypto Conditions
package ThresholdSha256

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/jtremback/crypto-conditions/ed25519sha256"
	"github.com/jtremback/crypto-conditions/encoding"
	"github.com/jtremback/crypto-conditions/sha256"
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

type WeightedString struct {
	Weight uint64
	String string
}

type WeightedStrings []WeightedString

func (a WeightedStrings) Len() int      { return len(a) }
func (a WeightedStrings) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a WeightedStrings) Less(i, j int) bool {
	// Sort lexicographically if the lengths are equal
	if len(a[i].String) == len(a[j].String) {
		return a[i].String < a[j].String
	}

	// Sort by length otherwise
	return len(a[i].String) < len(a[j].String)
}

type Fulfillment struct {
	Threshold       uint64
	SubFulfillments WeightedStrings
	SubConditions   WeightedStrings
	Length          uint64
}

func (wss *WeightedStrings) MakeVarray() []byte {
	b := []byte{}

	for _, ws := range *wss {
		b = append(b, encoding.MakeVarbyte(bytes.Join([][]byte{
			encoding.MakeUvarint(ws.Weight),
			encoding.MakeVarbyte([]byte(ws.String)),
		}, []byte{}))...)
	}

	return b
}

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
			Weight: w,
			String: string(s),
		})
	}

	return ws, nil
}

func (ful *Fulfillment) Serialize() string {
	sort.Sort(WeightedStrings(ful.SubFulfillments))
	sort.Sort(WeightedStrings(ful.SubConditions))
	payload := base64.URLEncoding.EncodeToString(bytes.Join([][]byte{
		encoding.MakeUvarint(ful.Threshold),
		encoding.MakeVarbyte(ful.SubFulfillments.MakeVarray()),
		encoding.MakeVarbyte(ful.SubConditions.MakeVarray()),
	}, []byte{}))

	return "cf:1:8:" + payload
}

// Parses Fulfillment out of the Crypto Conditions string format,
// and checks it for validity.
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

	if parts[2] != "4" {
		return nil, errors.New("not a sha256Threshold condition")
	}

	b, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("parsing error")
	}

	threshold, b, err := encoding.GetUvarint(b)
	if err != nil {
		return nil, err
	}

	fulfillments, b, err := encoding.GetVarbyte(b)
	if err != nil {
		return nil, err
	}

	subFulfillments, err := ParseWeightedStrings(fulfillments)
	if err != nil {
		return nil, err
	}

	conditions, b, err := encoding.GetVarbyte(b)
	if err != nil {
		return nil, err
	}

	subConditions, err := ParseWeightedStrings(conditions)
	if err != nil {
		return nil, err
	}

	ful := &Fulfillment{
		Threshold:       threshold,
		SubFulfillments: subFulfillments,
		SubConditions:   subConditions,
		Length:          uint64(len(s)),
	}

	var validWeight uint64
	for i, ws := range ful.SubFulfillments {
		cond, err := entry(ws.String)
		if err == nil && cond == ful.SubConditions[i].String {
			validWeight += ws.Weight
		}
	}

	if validWeight < ful.Threshold {
		return nil, errors.New("too many invalid fulfillments")
	}

	return ful, nil
}

func entry(ful string) (string, error) {
	parts := strings.Split(ful, ":")
	if len(parts) != 4 {
		return "", errors.New("parsing error")
	}

	if parts[0] != "cf" {
		return "", errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return "", errors.New("must be protocol version 1")
	}

	switch parts[2] {
	case "1":
		return Sha256.FulfillmentToCondition(ful)
	case "2":
		return Ed25519Sha256.FulfillmentToCondition(ful)
	case "4":
		return FulfillmentToCondition(ful)
	default:
		return "", errors.New("unsupported condition type")
	}
}

// Turns an in-memory Fulfillment to an in-memory Condition.
func (ful *Fulfillment) Condition() Condition {
	return Condition{
		Threshold:            ful.Threshold,
		SubConditions:        ful.SubConditions,
		MaxFulfillmentLength: ful.Length,
	}
}

type Condition struct {
	Threshold            uint64
	SubConditions        WeightedStrings
	MaxFulfillmentLength uint64
}

// Serializes to the Crypto Conditions string format.
func (cond *Condition) Serialize() string {
	hash := sha256.Sum256(bytes.Join([][]byte{
		encoding.MakeUvarint(8),
		encoding.MakeUvarint(cond.Threshold),
		encoding.MakeVarbyte(cond.SubConditions.MakeVarray()),
	}, []byte{}))

	return "cc:1:8:" + base64.URLEncoding.EncodeToString(hash[:]) + ":" + strconv.FormatUint(cond.MaxFulfillmentLength, 10)
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
