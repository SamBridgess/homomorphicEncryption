package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")
}

type testBfv struct {
	name     string
	input    int64
	expected int64
}

func TestBfvEncDec(t *testing.T) {
	assert := assert.New(t)

	tests := []testBfv{
		{"positive", 1, 1},
		{"positive", 100, 100},
		{"positive", 10000, 10000},
		{"negative", -1, -1},
		{"negative", -100, -100},
		{"negative", -10000, -10000},
		{"zero", 0, 0},
	}
	testsOutOfBound := []testBfv{
		{"positive_out_of_bound", 100000, 100000},
		{"negative_out_of_bound", -100000, -100000},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, err := he.EncryptBFV(currentTest.input)
			assert.NoError(err, "Error encrypting original data")

			decrypted, err := he.DecryptBFV(encrypted)
			assert.NoError(err, "Error decrypting original data")

			assert.Equal(decrypted, currentTest.expected, "Decrypted value is different from original value")
		})
	}

	for _, currentTest := range testsOutOfBound {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, err := he.EncryptBFV(currentTest.input)
			assert.NoError(err, "Error encrypting original data")

			decrypted, err := he.DecryptBFV(encrypted)
			assert.NoError(err, "Error decrypting original data")

			assert.NotEqual(decrypted, currentTest.expected, "Decrypted value is different from original value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := he.DecryptBFV(wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}
