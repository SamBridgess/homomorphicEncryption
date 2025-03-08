package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

// EncryptBFV Encrypts float64 data into []byte using BVF algorithm
func EncryptBFV(data []int64) ([]byte, error) {
	encoder := bfv.NewEncoder(BfvParams)
	encryptor := bfv.NewEncryptor(BfvParams, Keys.Pk)

	plaintext := bfv.NewPlaintext(BfvParams)
	//encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())
	encoder.EncodeInt(data, plaintext)

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

// DecryptBFV Decrypts data encrypted with BVF algorithm into a float64
func DecryptBFV(data []byte) (int64, error) {
	decryptor := bfv.NewDecryptor(BfvParams, Keys.Sk)

	ciphertext := bfv.NewCiphertext(BfvParams, 1)
	err := ciphertext.UnmarshalBinary(data)
	if err != nil {
		return 0, err
	}

	plaintext := decryptor.DecryptNew(ciphertext)

	encoder := bfv.NewEncoder(BfvParams)
	decoded := encoder.DecodeIntNew(plaintext)

	return decoded[0], nil
}
