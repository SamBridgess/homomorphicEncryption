package homomorphic_encryption_lib

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
)

var CkksParams ckks.Parameters
var BfvParams bfv.Parameters

// SetupServer Loads secret and public keys from file or generates new keys
// and saves them to file if such location doesn't exist.
// Sets up CkksParams on server side
func SetupServer(ckksKeysFileLocation string, bfvKeysFileLocation string) {
	var err error
	CkksParams, err = ckks.NewParametersFromLiteral(ckks.PN14QP438)
	BfvParams, err = bfv.NewParametersFromLiteral(bfv.PN14QP438)
	if err != nil {
		panic(err)
	}
	LoadOrGenerateKeys(ckksKeysFileLocation, CKKS)
	LoadOrGenerateKeys(bfvKeysFileLocation, BFV)
}
