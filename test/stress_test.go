package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	serverUrl = "https://127.0.0.1:443"
)

func init() {
	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")
}

func TestStressBfv(t *testing.T) {
	assert := assert.New(t)

	for i := 0; i < 100; i++ {
		data, _ := he.EncryptBFV(int64(10))

		// simulate network send
		go func() {
			_, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", data)
			assert.NoError(err, "Error sending bfv request")
		}()
		go func() {
			_, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", data)
			assert.NoError(err, "Error sending bfv request")
		}()
		go func() {
			_, err := he.SendComputationResultToServerBfv(serverUrl+"/decrypt_computations_bfv", data)
			assert.NoError(err, "Error sending bfv request")
		}()
	}
}

func TestStressCkks(t *testing.T) {
	assert := assert.New(t)

	for i := 0; i < 100; i++ {
		data, _ := he.EncryptCKKS(10.0)

		// simulate network send
		go func() {
			_, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", data)
			assert.NoError(err, "Error sending ckks request")
		}()
		go func() {
			_, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", data)
			assert.NoError(err, "Error sending ckks request")
		}()
		go func() {
			_, err := he.SendComputationResultToServerCkks(serverUrl+"/decrypt_computations_ckks", data)
			assert.NoError(err, "Error sending ckks request")
		}()
	}
}
