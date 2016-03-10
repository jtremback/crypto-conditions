package Sha256Hashlock

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func MakeFulfillment(pre []byte) string {
	return "cf:1:1:" + base64.URLEncoding.EncodeToString(pre)
}

func ConditionFromFulfillment(ful string) (string, error) {
	parts := strings.Split(ful, ":")

	if parts[0] != "cf" {
		return "", errors.New("fulfillments must start with \"cf\"")
	}

	if parts[1] != "1" {
		return "", errors.New("must be protocol version 1")
	}

	if parts[2] != "1" {
		return "", errors.New("not a Sha256 condition")
	}

	pre, err := base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", errors.New("parsing error")
	}

	hash := sha256.Sum256(pre)
	b64 := base64.URLEncoding.EncodeToString(hash[:])
	length := fmt.Sprintf("%d", len(ful))

	return "cc:1:1:" + b64 + ":" + length, nil
}
