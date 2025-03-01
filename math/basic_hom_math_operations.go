package math

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

func getNewEvaluator(ckksParams ckks.Parameters) ckks.Evaluator {
	// ignore the evaluation key
	var evalKey rlwe.EvaluationKey
	return ckks.NewEvaluator(ckksParams, evalKey)
}

func MakeZeroCipherText(evaluator ckks.Evaluator, ckksParams ckks.Parameters, encryptedData []byte) (*ckks.Ciphertext, error) {
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
