package test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/jtremback/crypto-conditions/ed25519sha256"
	"github.com/jtremback/crypto-conditions/encoding"
	"github.com/jtremback/crypto-conditions/sha256"
)

func TestVarStuff(t *testing.T) {

	empty := encoding.MakeVarbyte([]byte{})

	if bytes.Compare(empty, []byte{0}) != 0 {
		t.Fatal(empty)
	}

	fmt.Println(empty)

	buffer := [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}

	fmt.Println(buffer)

	seri := encoding.MakeVarray(buffer)
	if !reflect.DeepEqual(seri, []byte{15, 5, 1, 1, 1, 1, 1, 3, 2, 2, 2, 4, 3, 3, 3, 3}) {
		t.Fatal(seri)
	}
	fmt.Println(seri)

	deseri, length := encoding.ParseVarray(seri)
	if length != 15 {
		t.Fatal(length)
	}
	if !reflect.DeepEqual(deseri, [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}) {
		t.Fatal(deseri)
	}
	fmt.Println(deseri)
}

func TestMakeSha256Fulfillment(t *testing.T) {
	pre := []byte("foo")

	ful := Sha256.MakeFulfillment(pre)

	if ful != "cf:1:1:Zm9v" {
		t.Fatal(ful)
	}
	fmt.Println(ful)
}

func TestConditionFromSha256Fulfillment(t *testing.T) {
	pre := []byte("foo")

	ful := Sha256.Fulfillment(pre)

	cond, err := sha256.ConditionFromFulfillment(ful)
	if err != nil {
		t.Fatal(err)
	}

	if cond != "cc:1:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564=:11" {
		t.Fatal(cond)
	}
	fmt.Println(cond)
}

func TestMakeEd25519Sha256Fulfillment(t *testing.T) {
	ful := Ed25519Sha256.Fulfillment{
		PublicKey:      []byte{197, 198, 13, 156, 213, 181, 160, 15, 105, 7, 66, 222, 66, 15, 212, 8, 172, 55, 20, 47, 34, 182, 117, 106, 213, 203, 6, 172, 119, 66, 87, 170},
		MessageId:      []byte("foo"),
		FixedMessage:   []byte("fixed"),
		DynamicMessage: []byte("dyn"),
	}
}

// Extra keys
// &[197 198 13 156 213 181 160 15 105 7 66 222 66 15 212 8 172 55 20 47 34 182 117 106 213 203 6 172 119 66 87 170] &[244 9 180 60 13 13 60 215 158 30 236 128 111 107 44 54 75 151 209 13 20 19 58 42 162 147 207 0 189 188 4 136 197 198 13 156 213 181 160 15 105 7 66 222 66 15 212 8 172 55 20 47 34 182 117 106 213 203 6 172 119 66 87 170]
// &[236 129 33 67 119 101 27 246 101 161 109 184 246 50 2 214 184 162 40 197 194 196 212 210 163 136 39 229 123 204 82 25] &[97 111 164 221 195 25 249 6 17 161 159 191 252 118 241 114 92 113 7 100 234 111 160 131 230 22 181 67 197 183 9 99 236 129 33 67 119 101 27 246 101 161 109 184 246 50 2 214 184 162 40 197 194 196 212 210 163 136 39 229 123 204 82 25]
// &[118 97 30 186 23 231 51 77 244 88 148 216 9 177 104 120 183 209 212 48 44 133 220 62 24 92 165 7 153 68 194 83] &[117 54 222 53 77 11 219 41 154 161 185 104 208 248 30 59 132 230 116 108 150 60 215 9 221 101 210 53 150 159 129 174 118 97 30 186 23 231 51 77 244 88 148 216 9 177 104 120 183 209 212 48 44 133 220 62 24 92 165 7 153 68 194 83]
