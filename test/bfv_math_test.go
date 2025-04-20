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

type testBfvMath struct {
	name     string
	value1   int64
	value2   int64
	expected int64
}

type testBfvMathPositiveConst struct {
	name     string
	value1   int64
	value2   uint64
	expected int64
}

func TestBfvMultByPositiveConst(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfvMathPositiveConst{
		{"positive", 2, 1, 2},
		{"positive", 2, 100, 200},
		{"positive", 2, 10000, 20000},
		{"zero", 2, 0, 0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptBFV(currentTest.value1)

			operationResultBytes, err := bfvMath.MultByPositiveConst(encrypted1, currentTest.value2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptBFV(operationResultBytes)

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := bfvMath.MultByPositiveConst(wrongInput, 1)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestBfvSum(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfvMath{
		{"positive", 2, 1, 3},
		{"positive", 2, 100, 102},
		{"positive", 2, 10000, 10002},
		{"negative", 2, -3, -1},
		{"negative", 2, -100, -98},
		{"negative", 2, -10000, -9998},
		{"zero", 2, 0, 2},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptBFV(currentTest.value1)
			encrypted2, _ := he.EncryptBFV(currentTest.value2)

			operationResultBytes, err := bfvMath.Sum(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptBFV(operationResultBytes)

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptBFV(0.0)

		_, err := bfvMath.Sum(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = bfvMath.Sum(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestBfvSubtract(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfvMath{
		{"positive", 2, 1, 1},
		{"positive", 2, 100, -98},
		{"positive", 2, 10000, -9998},
		{"negative", 2, -3, 5},
		{"negative", 2, -100, 102},
		{"negative", 2, -10000, 10002},
		{"zero", 2, 0, 2},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptBFV(currentTest.value1)
			encrypted2, _ := he.EncryptBFV(currentTest.value2)

			operationResultBytes, err := bfvMath.Subtract(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptBFV(operationResultBytes)

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptBFV(0.0)

		_, err := bfvMath.Subtract(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = bfvMath.Subtract(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestBfvMult(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfvMath{
		{"positive", 2, 3.0, 6.0},
		{"positive", 2, 10000, 20000},
		{"negative", 2, -3, -6.0},
		{"negative", 2, -10000, -20000},
		{"zero", 2, 0, 0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptBFV(currentTest.value1)
			encrypted2, _ := he.EncryptBFV(currentTest.value2)

			operationResultBytes, err := bfvMath.Mult(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptBFV(operationResultBytes)

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptBFV(0.0)

		_, err := bfvMath.Mult(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = bfvMath.Mult(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}
