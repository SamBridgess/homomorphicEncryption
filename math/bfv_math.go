package math

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

// SumOf2_bfv Adds encryptedData to encryptedData2, producing []byte of encrypted data
// containing a sum of encryptedData data and encryptedData2 when decrypted
func SumOf2_bfv(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	BfvParams, err := bfv.NewParametersFromLiteral(bfv.PN14QP438)

	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	ciphertext2 := bfv.NewCiphertext(BfvParams, 1)

	err = ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	EvaluatorBfv := bfv.NewEvaluator(BfvParams, EvalKey)
	return EvaluatorBfv.AddNew(ciphertext, ciphertext2).MarshalBinary()
}

// MultOf2_bfv Multiplies encryptedData by encryptedData2, producing []byte of encrypted data
// containing a product of encryptedData and encryptedData2 when decrypted
func MultOf2_bfv(encryptedData []byte, encryptedData2 []byte) ([]byte, error) {
	BfvParams, err := bfv.NewParametersFromLiteral(bfv.PN14QP438)

	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	ciphertext2 := bfv.NewCiphertext(BfvParams, 1)

	err = ciphertext.UnmarshalBinary(encryptedData)
	if err != nil {
		return nil, err
	}

	err = ciphertext2.UnmarshalBinary(encryptedData2)
	if err != nil {
		return nil, err
	}

	EvaluatorBfv := bfv.NewEvaluator(BfvParams, EvalKey)
	return EvaluatorBfv.MulNew(ciphertext, ciphertext2).MarshalBinary()
}
