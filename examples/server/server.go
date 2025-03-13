package main

import (
	he "github.com/SamBridgess/homomorphicEncryption"
	_ "github.com/lib/pq"
	"log"
)

const (
	host           = "localhost"
	port           = 5432
	userServer     = "postgres"
	passwordServer = "123456"
	dbname         = "encrypted_db"
)

func main() {
	he.SetupServer("ckksKeys.json", "bfvKeys.json")

	encryptedDataCkks1, _ := he.EncryptCKKS(5.0)
	encryptedDataCkks2, _ := he.EncryptCKKS(4.0)
	encryptedDataCkks3, _ := he.EncryptCKKS(3.0)
	encryptedDataCkks4, _ := he.EncryptCKKS(2.0)
	encryptedDataCkks5, _ := he.EncryptCKKS(1.0)

	encryptedDataBfv1, _ := he.EncryptBFV(1)
	encryptedDataBfv2, _ := he.EncryptBFV(2)
	encryptedDataBfv3, _ := he.EncryptBFV(3)
	encryptedDataBfv4, _ := he.EncryptBFV(4)
	encryptedDataBfv5, _ := he.EncryptBFV(5)

	serverInsert(
		encryptedDataCkks1,
		encryptedDataCkks2,
		encryptedDataCkks3,
		encryptedDataCkks4,
		encryptedDataCkks5,

		encryptedDataBfv1,
		encryptedDataBfv2,
		encryptedDataBfv3,
		encryptedDataBfv4,
		encryptedDataBfv5,
	)

	log.Println("Server is running")
	he.StartSecureServer("443", "cert.pem", "key.pem")
}

func serverInsert(
	encryptedDataCkks1,
	encryptedDataCkks2,
	encryptedDataCkks3,
	encryptedDataCkks4,
	encryptedDataCkks5,

	encryptedDataBfv1,
	encryptedDataBfv2,
	encryptedDataBfv3,
	encryptedDataBfv4,
	encryptedDataBfv5 []byte,
) {
	psqlInfo := he.NewDBConnectionInfo(host, port, userServer, passwordServer, dbname)
	db, err := he.OpenConnection(psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(
		"INSERT INTO encrypted_data_ckks_bfv (encryptedDataCkks1, encryptedDataCkks2, encryptedDataCkks3, encryptedDataCkks4, encryptedDataCkks5, encryptedDataBfv1, encryptedDataBfv2, encryptedDataBfv3, encryptedDataBfv4, encryptedDataBfv5) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		encryptedDataCkks1,
		encryptedDataCkks2,
		encryptedDataCkks3,
		encryptedDataCkks4,
		encryptedDataCkks5,

		encryptedDataBfv1,
		encryptedDataBfv2,
		encryptedDataBfv3,
		encryptedDataBfv4,
		encryptedDataBfv5,
	)
	if err != nil {
		log.Fatal(err)
	}
}
