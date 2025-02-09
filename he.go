package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var (
	ckksParams, _ = ckks.NewParametersFromLiteral(ckks.PN12QP109)
)

func EncryptCKKS(data float64, pk *rlwe.PublicKey) ([]byte, error) {
	encoder := ckks.NewEncoder(ckksParams)
	encryptor := ckks.NewEncryptor(ckksParams, pk)

	plaintext := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, ckksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

func DecryptCKKS(data []byte, sk *rlwe.SecretKey) (float64, error) {
	decryptor := ckks.NewDecryptor(ckksParams, sk)
	ciphertext := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel(), ckksParams.DefaultScale())
	err := ciphertext.UnmarshalBinary(data)
	if err != nil {
		return 0, err
	}

	plaintext := decryptor.DecryptNew(ciphertext)
	encoder := ckks.NewEncoder(ckksParams)
	decoded := encoder.Decode(plaintext, ckksParams.LogSlots())

	return real(decoded[0]), nil
}
