package bfvMath

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"log"
)

type ConstOperation func([]byte, uint64) ([]byte, error)
type Operation2 func([]byte, []byte) ([]byte, error)

var BfvParams bfv.Parameters
var BfvEvaluator bfv.Evaluator
var BfvEvalKey rlwe.EvaluationKey

// unmarshallIntoNewCiphertext returns a new bfv.Ciphertext containing
// unmarshalled number from encryptedData
func unmarshallIntoNewCiphertext(encryptedData []byte) (*bfv.Ciphertext, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// makeZeroCiphertext Takes any encrypted data and subtracts it from itself
// making a *bfv.Ciphertext containing 0 when decrypted
func makeZeroCiphertext(someEncryptedData []byte) (*bfv.Ciphertext, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	err := ciphertext.UnmarshalBinary(someEncryptedData)
	if err != nil {
		return nil, err
	}
	return BfvEvaluator.SubNew(ciphertext, ciphertext), nil
}

// MultByPositiveConst Multiplies encryptedData by uint64 multValue, producing []byte of encrypted data
// containing a product of encryptedData and multValue when decrypted
func MultByPositiveConst(encryptedData []byte, multValue uint64) ([]byte, error) {
	ciphertext, err := unmarshallIntoNewCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Println("BFV: MultByPositiveConst success")
	return BfvEvaluator.MulScalarNew(ciphertext, multValue).MarshalBinary()
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

	log.Println("BFV: Sum success")
	return BfvEvaluator.AddNew(ciphertext, ciphertext2).MarshalBinary()
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

	log.Println("BFV: Subtract success")
	return BfvEvaluator.SubNew(ciphertext, ciphertext2).MarshalBinary()
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

	log.Println("BFV: Mult success")
	return BfvEvaluator.MulNew(ciphertext, ciphertext2).MarshalBinary()
}
