package homomorphic_encryption_lib

import (
	"database/sql"
	"fmt"
)

type DBConnectionInfo struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

func NewDBConnectionInfo(host string, port int, user string, password string, dbname string) DBConnectionInfo {
	info := DBConnectionInfo{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		DBName:   dbname,
	}
	return info
}

func OpenConnection(info DBConnectionInfo) (*sql.DB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", info.Host, info.Port, info.User, info.Password, info.DBName)
	return sql.Open("postgres", psqlInfo)
}
