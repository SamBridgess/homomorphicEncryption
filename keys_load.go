package homomorphic_encryption_lib

import (
	"encoding/json"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"os"
)

var Keys KeyPair

// KeyPair Struct containing rlwe.SecretKey and rlwe.PublicKey
type KeyPair struct {
	Sk *rlwe.SecretKey
	Pk *rlwe.PublicKey
}

// NewKeyPair Creates a new KeyPair struct
func NewKeyPair(Sk *rlwe.SecretKey, Pk *rlwe.PublicKey) KeyPair {
	pair := KeyPair{
		Sk: Sk,
		Pk: Pk,
	}
	return pair
}

// GenKeysCKKS Generates new KeyPair
func GenKeysCKKS() KeyPair {
	return NewKeyPair(bfv.NewKeyGenerator(BfvParams).GenKeyPair())
}

func LoadOrGenerateKeys(keysFileLocation string) {
	if _, err := os.Stat(keysFileLocation); os.IsNotExist(err) {
		fmt.Println("Keys file not found. Generating new keys")
		GenerateAndSaveKeys(keysFileLocation)
	} else {
		fmt.Println("Loading keys from file...")
		LoadKeys(keysFileLocation)
	}
}

// GenerateAndSaveKeys Generates new KeyPair and saves it to keysFileLocation
// json file
func GenerateAndSaveKeys(keysFileLocation string) {
	Keys = GenKeysCKKS()

	data, err := json.Marshal(Keys)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(keysFileLocation, data, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys generated and saved")
}

// LoadKeys Loads KeyPair from keysFileLocation json file
func LoadKeys(keysFileLocation string) {
	data, err := os.ReadFile(keysFileLocation)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(data, &Keys)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys loaded from file.")
}
