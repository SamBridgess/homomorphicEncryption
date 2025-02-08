package homomorphic_encryption_lib

import (
	"database/sql"
	"fmt"
)

func OpenConnection(host string, port int, user_server string, password_server string, dbname string) (*sql.DB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user_server, password_server, dbname)
	return sql.Open("postgres", psqlInfo)
}
