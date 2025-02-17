package homomorphic_encryption_lib

import (
	"encoding/json"
	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"os"
)

var Keys KeyPair

type KeyPair struct {
	Sk *rlwe.SecretKey
	Pk *rlwe.PublicKey
}

func NewKeyPair(Sk *rlwe.SecretKey, Pk *rlwe.PublicKey) KeyPair {
	pair := KeyPair{
		Sk: Sk,
		Pk: Pk,
	}
	return pair
}

func GenKeysCKKS() {
	Keys = NewKeyPair(ckks.NewKeyGenerator(CkksParams).GenKeyPair())
}

func LoadOrGenerateKeys(paramsFile string) {
	if _, err := os.Stat(paramsFile); os.IsNotExist(err) {
		fmt.Println("Keys file not found. Generating new keys")
		GenerateAndSaveKeys(paramsFile)
	} else {
		fmt.Println("Loading keys from file...")
		LoadKeys(paramsFile)
	}
}

func GenerateAndSaveKeys(paramsFile string) {
	GenKeysCKKS()

	data, err := json.Marshal(Keys)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(paramsFile, data, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys generated and saved")
}

func LoadKeys(paramsFile string) {
	data, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(data, &Keys)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys loaded from file.")
}
