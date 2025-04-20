package ckksMath

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"log"
)

type ConstOperation func([]byte, float64) ([]byte, error)
type Operation1 func([]byte) ([]byte, error)
type Operation2 func([]byte, []byte) ([]byte, error)

var CkksParams ckks.Parameters
var CkksEvaluator ckks.Evaluator
var CkksEvalkey rlwe.EvaluationKey

// unmarshallIntoNewCiphertext returns a new ckks.Ciphertext containing
// unmarshalled number from encryptedData
func unmarshallIntoNewCiphertext(encryptedData []byte) (*ckks.Ciphertext, error) {
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// makeZeroCiphertext Takes any encrypted data and subtracts it from itself
// making a *ckks.Ciphertext containing 0 when decrypted
func makeZeroCiphertext(someEncryptedData []byte) (*ckks.Ciphertext, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(someEncryptedData)
	if err != nil {
		return nil, err
	}
	return CkksEvaluator.SubNew(ciphertext, ciphertext), nil
}

// AddConst Adds a float64 addValue to encrypted data, producing []byte of encrypted data
// containing a sum of encryptedData data and addValue when decrypted
func AddConst(encryptedData []byte, addValue float64) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: AddConst success")
	return CkksEvaluator.AddConstNew(ciphertext, addValue).MarshalBinary()
}

// SubtractConst Subtracts a float64 subValue from encrypted data, producing []byte of encrypted data
// containing a difference of encryptedData data and subValue when decrypted
func SubtractConst(encryptedData []byte, subValue float64) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: SubtractConst success")
	return CkksEvaluator.AddConstNew(ciphertext, -subValue).MarshalBinary()
}

// MultByConst Multiplies encryptedData by float64 multValue, producing []byte of encrypted data
// containing a product of encryptedData and multValue when decrypted
func MultByConst(encryptedData []byte, multValue float64) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: MultByConst success")
	return CkksEvaluator.MultByConstNew(ciphertext, multValue).MarshalBinary()
}

// DivByConst Divides encryptedDataDividend by float64 encryptedDataDivisor, producing []byte of
// encrypted data containing a quotient of encryptedDataDividend and encryptedDataDivisor
// when decrypted
func DivByConst(encryptedDataDividend []byte, encryptedDataDivisor float64) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedDataDividend)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: DivByConst success")
	return CkksEvaluator.MultByConstNew(ciphertext, 1.0/encryptedDataDivisor).MarshalBinary()
}

// Sum Adds encryptedData to encryptedData2, producing []byte of encrypted data
// containing a sum of encryptedData data and encryptedData2 when decrypted
func Sum(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	ciphertext2, err := unmarshallIntoNewCiphertext(encryptedData2)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: Sum success")
	return CkksEvaluator.AddNew(ciphertext, ciphertext2).MarshalBinary()
}

// Subtract Subtracts encryptedData2 from encryptedData, producing []byte of encrypted data
// containing a difference of encryptedData data and encryptedData2 when decrypted
func Subtract(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	ciphertext2, err := unmarshallIntoNewCiphertext(encryptedData2)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: Subtract success")
	return CkksEvaluator.SubNew(ciphertext, ciphertext2).MarshalBinary()
}

// Mult Multiplies encryptedData by encryptedData2, producing []byte of encrypted data
// containing a product of encryptedData and encryptedData2 when decrypted
func Mult(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	ciphertext2, err := unmarshallIntoNewCiphertext(encryptedData2)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: Mult success")
	return CkksEvaluator.MulNew(ciphertext, ciphertext2).MarshalBinary()
}

// Pow2 raises encryptedData to the power of 2 by multiplying it to itself, producing []byte of
// encrypted data containing a power of 2 of encryptedData when decrypted
func Pow2(encryptedData []byte) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Println("CKKS: Pow2 success")
	return CkksEvaluator.MulNew(ciphertext, ciphertext).MarshalBinary()
}
