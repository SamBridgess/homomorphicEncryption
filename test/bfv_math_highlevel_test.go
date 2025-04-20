package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/SamBridgess/homomorphicEncryption/bfvMath"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")
	he.SetupClient(he.CkksParams, he.BfvParams, he.EvalKeysCkks.EvalKey1, he.EvalKeysBfv.EvalKey1)
}

type testBfvArrayMath struct {
	name     string
	value    []int64
	expected int64
}

func TestBfvArraySum(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfvArrayMath{
		{"positive", []int64{1, 2, 3}, 6},
		{"positive", []int64{-1, -2, -3}, -6},
		{"zero", []int64{0, 0, 0}, 0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptBFV(currentTest.value[0])
			encrypted2, _ := he.EncryptBFV(currentTest.value[1])
			encrypted3, _ := he.EncryptBFV(currentTest.value[2])

			operationResultBytes, err := bfvMath.ArraySum([][]byte{encrypted1, encrypted2, encrypted3})
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptBFV(operationResultBytes)

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := bfvMath.ArraySum([][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = bfvMath.ArraySum([][]byte{})
		assert.Error(err, "Didn't get expected error")
	})
}
