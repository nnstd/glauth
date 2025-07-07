package database

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nnstd/glauth/v2/pkg/handler"
)

// DatabaseType represents the type of database to use
type DatabaseType string

const (
	SQLite     DatabaseType = "sqlite"
	MySQL      DatabaseType = "mysql"
	PostgreSQL DatabaseType = "postgres"
)

// NewHandler creates a new database handler based on the database type
func NewHandler(dbType DatabaseType, opts ...handler.Option) (handler.Handler, error) {
	switch dbType {
	case SQLite:
		return NewSQLiteHandler(opts...), nil
	case MySQL:
		return NewMySQLHandler(opts...), nil
	case PostgreSQL:
		return NewPostgresHandler(opts...), nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
}

// DetectDatabaseType attempts to detect the database type from a connection string
func DetectDatabaseType(connectionString string) (DatabaseType, error) {
	if connectionString == "" {
		return "", errors.New("empty connection string")
	}

	// SQLite detection - typically just a file path
	if !strings.Contains(connectionString, "://") && !strings.Contains(connectionString, "@") {
		return SQLite, nil
	}

	// MySQL detection
	if strings.Contains(connectionString, "tcp(") || strings.Contains(connectionString, "mysql://") {
		return MySQL, nil
	}

	// PostgreSQL detection
	if strings.Contains(connectionString, "host=") || strings.Contains(connectionString, "postgres://") || strings.Contains(connectionString, "postgresql://") {
		return PostgreSQL, nil
	}

	// Default to SQLite for simple file paths
	return SQLite, nil
}
