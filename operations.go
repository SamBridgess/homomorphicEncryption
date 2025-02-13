package homomorphic_encryption_lib

import (
	"errors"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

func getNewEvaluator(ckksParams ckks.Parameters) ckks.Evaluator {
	// ignore the evaluation key
	var evalKey rlwe.EvaluationKey
	return ckks.NewEvaluator(ckksParams, evalKey)
}

func makeZeroCipherText(evaluator ckks.Evaluator, ckksParams ckks.Parameters, encryptedData []byte) (*ckks.Ciphertext, error) {
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}
	return evaluator.SubNew(ciphertext, ciphertext), nil
}

func AddConst(encryptedData []byte, addValue int, ckksParams ckks.Parameters) ([]byte, error) {
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	evaluator := getNewEvaluator(ckksParams)
	return evaluator.AddConstNew(ciphertext, addValue).MarshalBinary()
}

func MultByConst(encryptedData []byte, multValue int, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)

	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	return evaluator.MultByConstNew(ciphertext, multValue).MarshalBinary()
}

func SumOf2(encryptedData []byte, encryptedData2 []byte, ckksParams ckks.Parameters) ([]byte, error) {
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
	return evaluator.AddNew(ciphertext, ciphertext2).MarshalBinary()
}

func MultOf2(encryptedData []byte, encryptedData2 []byte, ckksParams ckks.Parameters) ([]byte, error) {
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
	return evaluator.MulNew(ciphertext, ciphertext2).MarshalBinary()
}

func DivByConst(encryptedData []byte, divisor float64, ckksParams ckks.Parameters) ([]byte, error) {
	evaluator := getNewEvaluator(ckksParams)

	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	return evaluator.MultByConstNew(ciphertext, 1.0/divisor).MarshalBinary()
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

func ArraySum(encryptedDataArray [][]byte, ckksParams ckks.Parameters) ([]byte, error) {
	if len(encryptedDataArray) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	evaluator := getNewEvaluator(ckksParams)

	sumCiphertext, err := makeZeroCipherText(evaluator, ckksParams, encryptedDataArray[0])
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
