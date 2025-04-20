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

type testCkksArrayMath struct {
	name     string
	value    []float64
	expected float64
}

func TestCkksArraySum(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 3.0}, 6.0},
		{"positive", []float64{-1.0, -2.0, -3.0}, -6.0},
		{"zero", []float64{0.0, 0.0, 0.0}, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.ArraySum([][]byte{encrypted1, encrypted2, encrypted3})
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-5, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.ArraySum([][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.ArraySum([][]byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksArrayMean(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 3.0}, 2.0},
		{"positive", []float64{-1.0, -2.0, -3.0}, -2.0},
		{"zero", []float64{0.0, 0.0, 0.0}, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.ArrayMean([][]byte{encrypted1, encrypted2, encrypted3})
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-5, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.ArrayMean([][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.ArrayMean([][]byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksVariance(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 3.0}, 0.66666},
		{"positive", []float64{-1.0, -2.0, -3.0}, 0.66666},
		{"zero", []float64{0.0, 0.0, 0.0}, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.Variance([][]byte{encrypted1, encrypted2, encrypted3})
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-5, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.Variance([][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Variance([][]byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksCovariance(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 3.0}, 0.66666},
		{"positive", []float64{-1.0, -2.0, -3.0}, 0.66666},
		{"zero", []float64{0.0, 0.0, 0.0}, 0.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.Covariance([][]byte{encrypted1, encrypted2, encrypted3}, [][]byte{encrypted1, encrypted2, encrypted3})
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-5, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.Covariance([][]byte{wrongInput, wrongInput, wrongInput}, [][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Covariance([][]byte{wrongInput, wrongInput}, [][]byte{wrongInput, wrongInput, wrongInput})
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.Covariance([][]byte{}, [][]byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksArithmeticProgressionElementN(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 5.0}, 9.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.ArithmeticProgressionElementN(encrypted1, encrypted2, encrypted3)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-3, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.ArithmeticProgressionElementN(wrongInput, wrongInput, wrongInput)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.ArithmeticProgressionElementN([]byte{}, []byte{}, []byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

func TestCkksArithmeticProgressionSum(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksArrayMath{
		{"positive", []float64{1.0, 2.0, 5.0}, 25.0},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.value[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.value[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.value[2])

			operationResultBytes, err := ckksMath.ArithmeticProgressionSum(encrypted1, encrypted2, encrypted3)
			assert.NoError(err, "Error performing operation")

			decrypted, _ := he.DecryptCKKS(operationResultBytes)

			assert.InDelta(decrypted, currentTest.expected, 1e-3, "Decrypted value is not equal to expected value")
		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.ArithmeticProgressionSum(wrongInput, wrongInput, wrongInput)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.ArithmeticProgressionSum([]byte{}, []byte{}, []byte{})
		assert.Error(err, "Didn't get expected error")
	})
}

type testCkksMovingAverage struct {
	name       string
	array      []float64
	windowSize int
	expected   []float64
}

func TestCkksMovingAverage(t *testing.T) {
	assert := assert.New(t)

	tests := []testCkksMovingAverage{
		{"positive", []float64{1.0, 2.0, 3.0}, 2.0, []float64{1.5, 2.5}},
	}
	wrongInput := []byte{0x00, 0x00, 0x00}

	for _, currentTest := range tests {
		t.Run(currentTest.name, func(t *testing.T) {
			encrypted1, _ := he.EncryptCKKS(currentTest.array[0])
			encrypted2, _ := he.EncryptCKKS(currentTest.array[1])
			encrypted3, _ := he.EncryptCKKS(currentTest.array[2])

			operationResultBytes, err := ckksMath.MovingAverage([][]byte{encrypted1, encrypted2, encrypted3}, currentTest.windowSize)
			assert.NoError(err, "Error performing operation")

			decrypted1, _ := he.DecryptCKKS(operationResultBytes[0])
			decrypted2, _ := he.DecryptCKKS(operationResultBytes[1])

			assert.InDelta(decrypted1, currentTest.expected[0], 1e-3, "Decrypted value is not equal to expected value")
			assert.InDelta(decrypted2, currentTest.expected[1], 1e-3, "Decrypted value is not equal to expected value")

		})
	}

	t.Run("wrong input", func(t *testing.T) {
		_, err := ckksMath.MovingAverage([][]byte{wrongInput, wrongInput, wrongInput}, 1.0)
		assert.Error(err, "Didn't get expected error")

		_, err = ckksMath.MovingAverage([][]byte{[]byte{}, []byte{}, []byte{}}, 1.0)
		assert.Error(err, "Didn't get expected error")
	})
}
