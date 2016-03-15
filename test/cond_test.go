package test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jtremback/crypto-conditions/ThresholdSha256"
	"github.com/jtremback/crypto-conditions/ed25519sha256"
	"github.com/jtremback/crypto-conditions/encoding"
	"github.com/jtremback/crypto-conditions/sha256"
)

var pubkey1 = [32]byte{197, 198, 13, 156, 213, 181, 160, 15, 105, 7, 66, 222, 66, 15, 212, 8, 172, 55, 20, 47, 34, 182, 117, 106, 213, 203, 6, 172, 119, 66, 87, 170}

var privkey1 = [64]byte{244, 9, 180, 60, 13, 13, 60, 215, 158, 30, 236, 128, 111, 107, 44, 54, 75, 151, 209, 13, 20, 19, 58, 42, 162, 147, 207, 0, 189, 188, 4, 136, 197, 198, 13, 156, 213, 181, 160, 15, 105, 7, 66, 222, 66, 15, 212, 8, 172, 55, 20, 47, 34, 182, 117, 106, 213, 203, 6, 172, 119, 66, 87, 170}

func TestEncoding(t *testing.T) {

	b1 := encoding.MakeVarbyte([]byte{2, 2, 2})

	if !reflect.DeepEqual(b1, []byte{3, 2, 2, 2}) {
		t.Fatal(b1)
	}

	empty := encoding.MakeVarbyte([]byte{})

	if !reflect.DeepEqual(empty, []byte{0}) {
		t.Fatal(empty)
	}

	buffer := [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}

	fmt.Println(buffer)

	seri := encoding.MakeVarray(buffer)
	if !reflect.DeepEqual(seri, []byte{5, 1, 1, 1, 1, 1, 3, 2, 2, 2, 4, 3, 3, 3, 3}) {
		t.Fatal(seri)
	}
	fmt.Println(seri)

	deseri := encoding.ParseVarray(seri)
	if !reflect.DeepEqual(deseri, [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}) {
		t.Fatal(deseri)
	}
	fmt.Println(deseri)
}

func TestSha256Fulfillment(t *testing.T) {
	ful := &Sha256.Fulfillment{
		Preimage: []byte{42},
	}

	serialized := ful.Serialize()

	if serialized != "cf:1:1:Kg==" {
		t.Fatal("serialization incorrect", serialized)
	}

	parsed, err := Sha256.ParseFulfillment(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ful.Preimage, parsed.Preimage) {
		t.Fatal(errors.New("Preimage doesn't match"))
	}

	cond1 := parsed.Condition()
	cond1String := cond1.Serialize()

	cond2 := Sha256.Condition{
		Hash:                 [32]byte{18, 160, 246, 92, 178, 87, 56, 195, 37, 31, 45, 223, 171, 113, 41, 251, 128, 222, 15, 127, 5, 227, 225, 5, 204, 172, 47, 43, 113, 7, 110, 157},
		MaxFulfillmentLength: 11,
	}
	cond2String := cond2.Serialize()

	if cond1String != cond2String || cond1String != "cc:1:1:EqD2XLJXOMMlHy3fq3Ep-4DeD38F4-EFzKwvK3EHbp0=:11" {
		t.Fatal(errors.New("serialized condition doesn't match"))
	}

	// Make fulfillment from preimage

	ful = &Sha256.Fulfillment{
		Preimage:             []byte{42},
		MaxFulfillmentLength: 999,
	}

	cond := ful.Condition()
	serialized = cond.Serialize()

	if serialized != "cc:1:1:EqD2XLJXOMMlHy3fq3Ep-4DeD38F4-EFzKwvK3EHbp0=:999" {
		t.Fatal("serialization incorrect", serialized)
	}
}

func TestEd25519Sha256Fulfillment(t *testing.T) {
	ful := &Ed25519Sha256.Fulfillment{
		PublicKey:               pubkey1,
		MessageId:               []byte{2, 2, 2, 2, 2},
		FixedMessage:            []byte{42},
		DynamicMessage:          []byte{90},
		MaxDynamicMessageLength: 99999,
	}

	ful.Sign(privkey1)

	serialized := ful.Serialize()

	if serialized != "cf:1:8:IMXGDZzVtaAPaQdC3kIP1AisNxQvIrZ1atXLBqx3QleqBQICAgICASqfjQYBWkA2xX6p4XT02llNku672lV8FravSFvXd8-d1U35qBgkGDFsWSOh5AmIlePfSOLpe9lYjjRKamenZopT2FvtJTsN" {
		t.Fatal("serialization incorrect", serialized)
	}

	parsed, err := Ed25519Sha256.ParseFulfillment(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ful.PublicKey, parsed.PublicKey) {
		t.Fatal(errors.New("PublicKey doesn't match"))
	}
	if !reflect.DeepEqual(ful.MessageId, parsed.MessageId) {
		t.Fatal(errors.New("MessageId doesn't match"))
	}
	if !reflect.DeepEqual(ful.FixedMessage, parsed.FixedMessage) {
		t.Fatal(errors.New("FixedMessage doesn't match"))
	}
	if !reflect.DeepEqual(ful.DynamicMessage, parsed.DynamicMessage) {
		t.Fatal(errors.New("DynamicMessage doesn't match"))
	}
	if !reflect.DeepEqual(ful.MaxDynamicMessageLength, parsed.MaxDynamicMessageLength) {
		t.Fatal(errors.New("MaxDynamicMessageLength doesn't match"))
	}

	cond1 := parsed.Condition()
	cond1String := cond1.Serialize()

	cond2 := Ed25519Sha256.Condition{
		PublicKey:               pubkey1,
		MessageId:               []byte{2, 2, 2, 2, 2},
		FixedMessage:            []byte{42},
		MaxDynamicMessageLength: 99999,
	}
	cond2String := cond2.Serialize()

	if cond2String != cond1String {
		t.Fatal(errors.New("serialized condition doesn't match"))
		fmt.Println(cond1)
		fmt.Println(cond2)
	}
}

func TestThresholdSha256Fulfillment(t *testing.T) {
	ThresholdSha256.Fulfillment{}
}

// Extra keys
// &[197 198 13 156 213 181 160 15 105 7 66 222 66 15 212 8 172 55 20 47 34 182 117 106 213 203 6 172 119 66 87 170] &[244 9 180 60 13 13 60 215 158 30 236 128 111 107 44 54 75 151 209 13 20 19 58 42 162 147 207 0 189 188 4 136 197 198 13 156 213 181 160 15 105 7 66 222 66 15 212 8 172 55 20 47 34 182 117 106 213 203 6 172 119 66 87 170]
// &[236 129 33 67 119 101 27 246 101 161 109 184 246 50 2 214 184 162 40 197 194 196 212 210 163 136 39 229 123 204 82 25] &[97 111 164 221 195 25 249 6 17 161 159 191 252 118 241 114 92 113 7 100 234 111 160 131 230 22 181 67 197 183 9 99 236 129 33 67 119 101 27 246 101 161 109 184 246 50 2 214 184 162 40 197 194 196 212 210 163 136 39 229 123 204 82 25]
// &[118 97 30 186 23 231 51 77 244 88 148 216 9 177 104 120 183 209 212 48 44 133 220 62 24 92 165 7 153 68 194 83] &[117 54 222 53 77 11 219 41 154 161 185 104 208 248 30 59 132 230 116 108 150 60 215 9 221 101 210 53 150 159 129 174 118 97 30 186 23 231 51 77 244 88 148 216 9 177 104 120 183 209 212 48 44 133 220 62 24 92 165 7 153 68 194 83]
