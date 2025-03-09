package bfvMath

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

var BfvParams bfv.Parameters
var BfvEvaluator bfv.Evaluator

// MakeZeroCiphertext Takes any encrypted data and subtracts it from itself
// making a *bfv.Ciphertext containing 0 when decrypted
func MakeZeroCiphertext(someEncryptedData []byte) (*bfv.Ciphertext, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	err := ciphertext.UnmarshalBinary(someEncryptedData)
	if err != nil {
		return nil, err
	}
	return BfvEvaluator.SubNew(ciphertext, ciphertext), nil
}

// SumOf2 Adds encryptedData to encryptedData2, producing []byte of encrypted data
// containing a sum of encryptedData data and encryptedData2 when decrypted
func SumOf2(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	ciphertext2 := bfv.NewCiphertext(BfvParams, 1)

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	return BfvEvaluator.AddNew(ciphertext, ciphertext2).MarshalBinary()
}

// Subtract Subtracts encryptedData2 from encryptedData, producing []byte of encrypted data
// containing a difference of encryptedData data and encryptedData2 when decrypted
func Subtract(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	ciphertext2 := bfv.NewCiphertext(BfvParams, 1)

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	return BfvEvaluator.SubNew(ciphertext, ciphertext2).MarshalBinary()
}

// MultOf2 Multiplies encryptedData by encryptedData2, producing []byte of encrypted data
// containing a product of encryptedData and encryptedData2 when decrypted
func MultOf2(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	ciphertext2 := bfv.NewCiphertext(BfvParams, 1)

	err := ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	return BfvEvaluator.MulNew(ciphertext, ciphertext2).MarshalBinary()
}
