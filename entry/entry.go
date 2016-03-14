package entry

import (
	"errors"
	"strings"

	"github.com/jtremback/crypto-conditions/ThresholdSha256"
	"github.com/jtremback/crypto-conditions/ed25519sha256"
	"github.com/jtremback/crypto-conditions/sha256"
)

func FulfillmentToCondition(ful string) (string, error) {
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
		return ThresholdSha256.FulfillmentToCondition(ful)
	default:
		return "", errors.New("unsupported condition type")
	}
}
