package homomorphic_encryption_lib

import (
	"encoding/json"
	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"os"
)

var CkksParams ckks.Parameters

func LoadOrGenerateCKKSParams(paramsFile string) {
	if _, err := os.Stat(paramsFile); os.IsNotExist(err) {
		fmt.Println("CKKS params file not found. Generating new CKKS params")
		GenerateAndSaveCKKSParams(paramsFile)
	} else {
		fmt.Println("Loading CKKS params from file...")
		LoadCKKSParams(paramsFile)
	}
}

func GenerateAndSaveCKKSParams(paramsFile string) {
	GenerateNewCkksParams()

	data, err := json.Marshal(CkksParams)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(paramsFile, data, 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("CKKS params generated and saved")
}

func LoadCKKSParams(paramsFile string) {
	data, err := os.ReadFile(paramsFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(data, &CkksParams)
	if err != nil {
		panic(err)
	}

	fmt.Println("CKKS params loaded from file.")
}

func GenerateNewCkksParams() {
	CkksParams, _ = ckks.NewParametersFromLiteral(ckks.PN14QP438)
}
