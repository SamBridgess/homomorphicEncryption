package homomorphic_encryption_lib

import "github.com/ldsec/lattigo/v2/ckks"

var CkksParams ckks.Parameters

// SetupServer Loads secret and public keys from file or generates new keys
// and saves them to file if such location doesn't exist.
// Sets up CkksParams on server side
func SetupServer(keysFileLocation string) {
	LoadOrGenerateKeys(keysFileLocation)

	var err error
	CkksParams, err = ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}
}
