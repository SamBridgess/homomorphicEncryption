package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/SamBridgess/homomorphicEncryption/ckksMath"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")
	he.SetupClient(he.CkksParams, he.BfvParams, he.EvalKeysCkks.EvalKey1, he.EvalKeysBfv.EvalKey1)
}

type testCkksMath struct {
	name     string
	value1   float64
	value2   float64
	expected float64
}

func TestCkksAddConst(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, 5.0},
		{"positive", 2.0, 10000000.0, 10000002.0},
		{"negative", 2.0, -3.0, -1.0},
		{"negative", 2.0, -10000000.0, -9999998.0},
		{"zero", 2.0, 0.0, 2.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, _ := he.EncryptCKKS(currentTest.value1)

			operationResultBytes, err := ckksMath.AddConst(encrypted, currentTest.value2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-2, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.AddConst(wrongInput, 0.0)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksSubtractConst(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, -1.0},
		{"positive", 2.0, 10000000.0, -9999998.0},
		{"negative", 2.0, -3.0, 5.0},
		{"negative", 2.0, -10000000.0, 10000002.0},
		{"zero", 2.0, 0.0, 2.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, _ := he.EncryptCKKS(currentTest.value1)

			operationResultBytes, err := ckksMath.SubtractConst(encrypted, currentTest.value2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-2, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.SubtractConst(wrongInput, 0.0)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksMultiplyByConst(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, 6.0},
		{"positive", 2.0, 10000.0, 20000.0},
		{"negative", 2.0, -3.0, -6.0},
		{"negative", 2.0, -10000.0, -20000.0},
		{"zero", 2.0, 0.0, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, _ := he.EncryptCKKS(currentTest.value1)

			operationResultBytes, err := ckksMath.MultByConst(encrypted, currentTest.value2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-1, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.MultByConst(wrongInput, 0.0)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksDivByConst(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 10.0, 2.0, 5.0},
		{"positive", 10.0, 10.0, 1.0},
		{"positive", 10.0, 1.0, 10.0},
		{"positive", 100000.0, 2.0, 50000.0},
		{"negative", 10.0, -2.0, -5.0},
		{"negative", 10.0, -10.0, -1.0},
		{"negative", 10.0, -1.0, -10.0},
		{"negative", 100000.0, -2.0, -50000.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, _ := he.EncryptCKKS(currentTest.value1)

			operationResultBytes, err := ckksMath.DivByConst(encrypted, currentTest.value2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-1, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.DivByConst(wrongInput, 1.0)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksSum(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, 5.0},
		{"positive", 2.0, 10000000.0, 10000002.0},
		{"negative", 2.0, -3.0, -1.0},
		{"negative", 2.0, -10000000.0, -9999998.0},
		{"zero", 2.0, 0.0, 2.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value1)
			encrypted2, _ := he.EncryptCKKS(currentTest.value2)

			operationResultBytes, err := ckksMath.Sum(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-1, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptCKKS(0.0)

		_, err := ckksMath.Sum(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Sum(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksSubtract(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, -1.0},
		{"positive", 2.0, 10000000.0, -9999998.0},
		{"negative", 2.0, -3.0, 5.0},
		{"negative", 2.0, -10000000.0, 10000002.0},
		{"zero", 2.0, 0.0, 2.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value1)
			encrypted2, _ := he.EncryptCKKS(currentTest.value2)

			operationResultBytes, err := ckksMath.Subtract(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-1, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptCKKS(0.0)

		_, err := ckksMath.Subtract(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Subtract(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksMult(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 2.0, 3.0, 6.0},
		{"positive", 2.0, 10000.0, 20000.0},
		{"negative", 2.0, -3.0, -6.0},
		{"negative", 2.0, -10000.0, -20000.0},
		{"zero", 2.0, 0.0, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value1)
			encrypted2, _ := he.EncryptCKKS(currentTest.value2)

			operationResultBytes, err := ckksMath.Mult(encrypted1, encrypted2)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-1, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		encrypted, _ := he.EncryptCKKS(0.0)

		_, err := ckksMath.Mult(wrongInput, encrypted)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Mult(encrypted, wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksPow(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMath{
		{"positive", 1.0, 0.0, 1.0},
		{"positive", 10.0, 0.0, 100.0},
		{"positive", 100.0, 0.0, 10000.0},
		{"negative", -1.0, 0.0, 1.0},
		{"negative", -10.0, 0.0, 100.0},
		{"negative", -100.0, 0.0, 10000.0},
		{"zero", 0.0, 0.0, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted, _ := he.EncryptCKKS(currentTest.value1)

			operationResultBytes, err := ckksMath.Pow2(encrypted)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-2, "Decrypted value is not within the allowed delta")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.Pow2(wrongInput)
		assert.Error(err, "Didn't get expected error")
	})
}
