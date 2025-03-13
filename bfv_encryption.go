package homomorphicEncryption

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

// EncryptBFV Encrypts float64 data into []byte using BVF algorithm
func EncryptBFV(data int64) ([]byte, error) {
	encoder := bfv.NewEncoder(BfvParams)
	encryptor := bfv.NewEncryptor(BfvParams, BfvKeys.Pk)

	plaintext := bfv.NewPlaintext(BfvParams)
	encoder.EncodeInt([]int64{data}, plaintext)

	ciphertext := encryptor.EncryptNew(plaintext)

	return ciphertext.MarshalBinary()
}

// DecryptBFV Decrypts data encrypted with BVF algorithm into an int64
func DecryptBFV(data []byte) (int64, error) {
	decryptor := bfv.NewDecryptor(BfvParams, BfvKeys.Sk)
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
