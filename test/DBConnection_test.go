package test

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	host           = "localhost"
	port           = 5432
	userServer     = "postgres"
	passwordServer = "123456"
	dbname         = "encrypted_db"
)

func TestNewDBConnectionInfo(t *testing.T) {
	assert := assert.New(t)

	expectedDBConnectionInfo := he.DBConnectionInfo{
		Host:     host,
		Port:     port,
		User:     userServer,
		Password: passwordServer,
		DBName:   dbname,
	}

	DBConnectionInfo := he.NewDBConnectionInfo(host, port, userServer, passwordServer, dbname)

	assert.Equal(DBConnectionInfo, expectedDBConnectionInfo)
}

func TestOpenConnection(t *testing.T) {
	assert := assert.New(t)

	dDBConnectionInfo := he.DBConnectionInfo{
		Host:     host,
		Port:     port,
		User:     userServer,
		Password: passwordServer,
		DBName:   dbname,
	}

	_, err := he.OpenConnection(dDBConnectionInfo)
	assert.NoError(err, "Error opening database connection")
}
