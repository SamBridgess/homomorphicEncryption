package homomorphic_encryption_lib

import (
	"encoding/json"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"os"
)

type Method int

const (
	CKKS Method = iota
	BFV
)

var CkksKeys KeyPair
var BfvKeys KeyPair

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

// GenKeysCKKS Generates new KeyPair of ckks keys
func GenKeysCKKS() KeyPair {
	return NewKeyPair(ckks.NewKeyGenerator(CkksParams).GenKeyPair())
}

// GenKeysBFV Generates new KeyPair bfv keys
func GenKeysBFV() KeyPair {
	return NewKeyPair(bfv.NewKeyGenerator(BfvParams).GenKeyPair())
}

// LoadOrGenerateKeys checks if keys file exists and if it does - loads it
// If it doesn't - generates a new keys file for specified method
func LoadOrGenerateKeys(keysFileLocation string, method Method) {
	if _, err := os.Stat(keysFileLocation); os.IsNotExist(err) {
		fmt.Printf("Keys file '%s' not found. Generating new keys\n", keysFileLocation)
		GenerateAndSaveKeys(keysFileLocation, method)
	} else {
		fmt.Println("Loading keys from file...")
		LoadKeys(keysFileLocation, method)
	}
}

// GenerateAndSaveKeysCKKS Generates new KeyPair and saves it to keysFileLocation
// json file
func GenerateAndSaveKeys(keysFileLocation string, method Method) {
	var data []byte
	var err error

	switch method {
	case CKKS:
		CkksKeys = GenKeysCKKS()
		data, err = json.Marshal(CkksKeys)
		if err != nil {
			panic(err)
		}
		fmt.Println("CKKS keys generated and saved")
	case BFV:
		BfvKeys = GenKeysBFV()
		data, err = json.Marshal(BfvKeys)
		if err != nil {
			panic(err)
		}
		fmt.Println("BFV keys generated and saved")
	default:
		panic("unknown method")
	}

	err = os.WriteFile(keysFileLocation, data, 0644)
	if err != nil {
		panic(err)
	}
}

// LoadKeys Loads KeyPair from keysFileLocation json file
func LoadKeys(keysFileLocation string, method Method) {
	data, err := os.ReadFile(keysFileLocation)
	if err != nil {
		panic(err)
	}

	switch method {
	case CKKS:
		err = json.Unmarshal(data, &CkksKeys)
		if err != nil {
			panic(err)
		}
		fmt.Println("CKKS keys loaded from file.")
	case BFV:
		err = json.Unmarshal(data, &BfvKeys)
		if err != nil {
			panic(err)
		}
		fmt.Println("BFV keys loaded from file.")
	default:
		panic("unknown method")
	}
}
