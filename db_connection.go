package homomorphicEncryption

import (
	"database/sql"
	"fmt"
)

// DBConnectionInfo Struct containing all the info needed to connect to a database
type DBConnectionInfo struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

// NewDBConnectionInfo Creates new DBConnectionInfo struct
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

// OpenConnection Opens connection to a designated database
func OpenConnection(info DBConnectionInfo) (*sql.DB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", info.Host, info.Port, info.User, info.Password, info.DBName)
	return sql.Open("postgres", psqlInfo)
}
