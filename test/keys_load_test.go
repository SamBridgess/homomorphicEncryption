package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestKeysLoad(t *testing.T) {
	assert := assert.New(t)

	he.SetupServer("../examples/server/ckksKeys.json", "../examples/server/bfvKeys.json")

	he.SetupServer("ckksKeys.json", "bfvKeys.json")
	err := os.Remove("ckksKeys.json")
	assert.NoError(err, "Error deleting ckksKeys.json")

	err = os.Remove("bfvKeys.json")
	assert.NoError(err, "Error deleting bfvKeys.json")
}
