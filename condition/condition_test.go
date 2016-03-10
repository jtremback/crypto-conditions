package condition

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestVarStuff(t *testing.T) {

	empty := makeVarbyte([]byte{})

	if bytes.Compare(empty, []byte{0}) != 0 {
		t.Fatal(empty)
	}

	fmt.Println(empty)

	buffer := [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}

	fmt.Println(buffer)

	seri := makeVarray(buffer)
	if !reflect.DeepEqual(seri, []byte{15, 5, 1, 1, 1, 1, 1, 3, 2, 2, 2, 4, 3, 3, 3, 3}) {
		t.Fatal(seri)
	}
	fmt.Println(seri)

	deseri, length := parseVarray(seri)
	if length != 15 {
		t.Fatal(length)
	}
	if !reflect.DeepEqual(deseri, [][]byte{[]byte{1, 1, 1, 1, 1}, []byte{2, 2, 2}, []byte{3, 3, 3, 3}}) {
		t.Fatal(deseri)
	}
	fmt.Println(deseri)
}

func TestMakeSha256Fulfillment(t *testing.T) {
	var sha256 Sha256
	pre := []byte("foo")

	ful := sha256.MakeFulfillment(pre)

	if ful != "cf:1:1:Zm9v" {
		t.Fatal(ful)
	}
	fmt.Println(ful)
}

func TestConditionFromSha256Fulfillment(t *testing.T) {
	var sha256 Sha256
	pre := []byte("foo")

	ful := sha256.MakeFulfillment(pre)

	cond, err := sha256.ConditionFromFulfillment(ful)
	if err != nil {
		t.Fatal(err)
	}

	if cond != "cc:1:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564=:11" {
		t.Fatal(cond)
	}
	fmt.Println(cond)
}

func TestMakeRsaSha256Fulfillment(t *testing.T) {
	var rsaSha256 RsaSha256Fulfillment
}
