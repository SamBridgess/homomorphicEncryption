package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"log"
)

// EncryptCKKS Encrypts float64 data into []byte using CKKS algorithm
func EncryptCKKS(data float64) ([]byte, error) {
	encoder := ckks.NewEncoder(CkksParams)
	encryptor := ckks.NewEncryptor(CkksParams, CkksKeys.Pk)

	plaintext := ckks.NewPlaintext(CkksParams, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	log.Println("Data successfully encrypted (CKKS)")
	return ciphertext.MarshalBinary()
}

// DecryptCKKS Decrypts data encrypted with CKKS algorithm into a float64
func DecryptCKKS(data []byte) (float64, error) {
	decryptor := ckks.NewDecryptor(CkksParams, CkksKeys.Sk)
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(data)
	if err != nil {
		return 0, err
	}

	plaintext := decryptor.DecryptNew(ciphertext)
	encoder := ckks.NewEncoder(CkksParams)
	decoded := encoder.Decode(plaintext, CkksParams.LogSlots())

	log.Println("Data successfully decrypted (CKKS)")
	return real(decoded[0]), nil
}
