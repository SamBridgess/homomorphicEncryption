package math

import (
	"errors"
	"github.com/ldsec/lattigo/v2/ckks"
)

func ArraySum(encryptedDataArray [][]byte, ckksParams ckks.Parameters) ([]byte, error) {
	if len(encryptedDataArray) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	evaluator := getNewEvaluator(ckksParams)

	sumCiphertext, err := MakeZeroCipherText(evaluator, ckksParams, encryptedDataArray[0])
	if err != nil {
		return nil, err
	}

	for _, encryptedData := range encryptedDataArray {
		ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())

		err := ciphertext.UnmarshalBinary(encryptedData)
		evaluator.Add(sumCiphertext, ciphertext, sumCiphertext)
		if err != nil {
			return nil, err
		}
	}

	return sumCiphertext.MarshalBinary()
}

func Mean(encryptedDataArray [][]byte, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)

	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())

	sum, err := ArraySum(encryptedDataArray, ckksParams)
	if err != nil {
		return nil, err
	}

	err = ciphertext.UnmarshalBinary(sum)
	if err != nil {
		return nil, err
	}

	return evaluator.MultByConstNew(ciphertext, 1.0/float64(len(encryptedDataArray))).MarshalBinary()
}

func MovingAverage(encryptedDataArray [][]byte, windowSize int, ckksParams ckks.Parameters) ([][]byte, error) {
	movingArrayLen := len(encryptedDataArray) - windowSize
	r := make([][]byte, movingArrayLen)
	for i := 0; i < movingArrayLen; i++ {
		var err error
		r[i], err = Mean(encryptedDataArray[i:i+windowSize], ckksParams)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func Sqrt(encryptedData []byte, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	// Define the polynomial coefficients for sqrt(x) approximation
	coefficients := []float64{0.3725, 0.5, -0.045} // Example coefficients for P(x) = c0 + c1*x + c2*x^2

	result := evaluator.MultByConstNew(ciphertext, coefficients[2])     // x * c2
	result = evaluator.AddConstNew(result, complex(coefficients[1], 0)) // c1 + x*c2
	result = evaluator.MulNew(result, ciphertext)                       // x * (c1 + x*c2)
	result = evaluator.AddConstNew(result, complex(coefficients[0], 0)) // c0 + x*(c1 + x*c2)

	return result.MarshalBinary()
}
