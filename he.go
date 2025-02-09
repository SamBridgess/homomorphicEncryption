package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var (
	CkksParams, _ = ckks.NewParametersFromLiteral(ckks.PN12QP109)
)

func EncryptCKKS(data float64, pk *rlwe.PublicKey) ([]byte, error) {
	encoder := ckks.NewEncoder(CkksParams)
	encryptor := ckks.NewEncryptor(CkksParams, pk)

	plaintext := ckks.NewPlaintext(CkksParams, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

func DecryptCKKS(data []byte, sk *rlwe.SecretKey) (float64, error) {
	decryptor := ckks.NewDecryptor(CkksParams, sk)
	ciphertext := ckks.NewCiphertext(CkksParams, 1, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(data)
	if err != nil {
		return 0, err
	}

	plaintext := decryptor.DecryptNew(ciphertext)
	encoder := ckks.NewEncoder(CkksParams)
	decoded := encoder.Decode(plaintext, CkksParams.LogSlots())

	return real(decoded[0]), nil
}
