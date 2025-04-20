package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")
}

type testCkks struct {
	name     string
	input    float64
	expected float64
}

func TestCkksEncDec(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkks{
		{"positive", 1.0, 1.0},
		{"positive", 100.0, 100.0},
		{"positive", 10000000000000000000.0, 10000000000000000000.0},
		{"negative", -1.0, -1.0},
		{"negative", -100.0, -100.0},
		{"negative", -10000000000000000000.0, -10000000000000000000.0},
		{"zero", 0.0, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, err := he.EncryptCKKS(currentTest.input)
			assert.NoError(err, "Error encrypting original data")

			decrypted, err := he.DecryptCKKS(encrypted)
			assert.NoError(err, "Error decrypting original data")

			assert.InDelta(decrypted, currentTest.expected, 1e-5, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := he.DecryptCKKS(wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}
