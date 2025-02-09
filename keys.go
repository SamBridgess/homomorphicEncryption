package homomorphic_encryption_lib

import (
	"crypto/rand"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
)

func GenKeysCKKS(ckksParams ckks.Parameters) (*rlwe.SecretKey, *rlwe.PublicKey) {
	return ckks.NewKeyGenerator(ckksParams).GenKeyPair()
}

func GenKeyAES() ([]byte, error) {
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	return aesKey, err
}

func GenKeyEval() *rlwe.EvaluationKey {
	return nil
}
