package bfvMath

import (
	"errors"
	"github.com/ldsec/lattigo/v2/bfv"
)

// ArraySum Returns the encrypted sum of all elements of passed array in []byte
func ArraySum(encryptedDataArray [][]byte) ([]byte, error) {
	if len(encryptedDataArray) == 0 {
		return nil, errors.New("cannot use empty array")
	}

	sumCiphertext, err := makeZeroCiphertext(encryptedDataArray[0])
	if err != nil {
		return nil, err
	}

	for _, encryptedData := range encryptedDataArray {
		ciphertext := bfv.NewCiphertext(BfvParams, 1)

		err := ciphertext.UnmarshalBinary(encryptedData)
		BfvEvaluator.Add(sumCiphertext, ciphertext, sumCiphertext)

		if err != nil {
			return nil, err
		}
	}

	return sumCiphertext.MarshalBinary()
}
