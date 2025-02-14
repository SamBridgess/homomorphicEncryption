package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var (
	CkksParams ckks.Parameters
	Sk         *rlwe.SecretKey
	Pk         *rlwe.PublicKey
)

func GenNewCkksParams() {
	CkksParams, _ = ckks.NewParametersFromLiteral(ckks.PN12QP109)
}

func GenKeysCKKS() {
	Sk, Pk = ckks.NewKeyGenerator(CkksParams).GenKeyPair()
}

func EncryptCKKS(data float64) ([]byte, error) {
	encoder := ckks.NewEncoder(CkksParams)
	encryptor := ckks.NewEncryptor(CkksParams, Pk)

	plaintext := ckks.NewPlaintext(CkksParams, CkksParams.MaxLevel(), CkksParams.DefaultScale())
	encoder.Encode([]float64{data}, plaintext, CkksParams.LogSlots())

	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

func DecryptCKKS(data []byte) (float64, error) {
	decryptor := ckks.NewDecryptor(CkksParams, Sk)
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
