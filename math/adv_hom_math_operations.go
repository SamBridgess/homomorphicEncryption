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

func Sqrt(encryptedData []byte, coefficients []float64, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	//coefficients := []float64{-0.01889609, 0.44417952, 0.51442034}
	xSquared := evaluator.MulNew(ciphertext, ciphertext)
	term2 := evaluator.MultByConstNew(xSquared, coefficients[2])
	term1 := evaluator.MultByConstNew(ciphertext, coefficients[1])
	result := evaluator.AddNew(term1, term2)
	result = evaluator.AddConstNew(result, complex(coefficients[0], 0))

	return result.MarshalBinary()
}

func Divide(encryptedData []byte, encryptedData2 []byte, iterations int, apr int, ckksParams ckks.Parameters) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	ciphertext2 := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	evaluator := getNewEvaluator(ckksParams)

	inverseC2 := InverseNewton(evaluator, ciphertext2, iterations, apr)

	return evaluator.MulNew(ciphertext, inverseC2).MarshalBinary()
}

func InverseNewton(evaluator ckks.Evaluator, ciphertext *ckks.Ciphertext, iterations int, apr int) *ckks.Ciphertext {
	x := evaluator.MultByConstNew(ciphertext, apr)
	for i := 0; i < iterations; i++ {
		ax := evaluator.MulNew(ciphertext, x)
		twoMinusAX := evaluator.AddConstNew(ax, -1.0) // 2 - a * x_n

		x = evaluator.MulNew(x, twoMinusAX)
	}
	return x
}
