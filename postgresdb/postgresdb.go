// Package postgresdb handles connection and SQL queries to Vulscano Postgres DB
package postgresdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/lucabrasi83/vulscano/initializer" // Import for correct init functions order
	"github.com/lucabrasi83/vulscano/logging"
)

// ConnPool represents the Connection Pool instance
// db represents an instance of Postgres connection pool
var ConnPool *pgxpool.Pool
var DBInstance *vulscanoDB
var connPoolConfig pgxpool.Config
var pgpSymEncryptKey = os.Getenv("VSCAN_SECRET_KEY")

const (
	shortQueryTimeout  = 30 * time.Second
	mediumQueryTimeout = 3 * time.Minute
	longQueryTimeout   = 10 * time.Minute
)

type vulscanoDB struct {
	db *pgxpool.Pool
}

// init() function will establish DB connection pool while package is being loaded.
func init() {

	// Check Environment Variables for Postgres DB Credentials
	if os.Getenv("VULSCANO_DB_USERNAME") == "" || os.Getenv("VULSCANO_DB_PASSWORD") == "" {
		logging.VulscanoLog("fatal",
			"Missing Environment Variable(s) for PostgresDB Connection not set ",
			"(VULSCANO_DB_USERNAME / VULSCANO_DB_PASSWORD)")
	}

	// Check Environment Variables for Postgres Hostname
	if os.Getenv("VULSCANO_DB_HOST") == "" {
		logging.VulscanoLog("fatal",
			"Missing Environment Variable for PostgresDB Hostname ",
			"VULSCANO_DB_HOST")
	}

	// Check Environment Variables for Postgres Database Name
	if os.Getenv("VULSCANO_DB_DATABASE_NAME") == "" {
		logging.VulscanoLog("fatal",
			"Missing Environment Variable for PostgresDB Database Name ",
			"VULSCANO_DB_DATABASE_NAME")
	}

	// Check Environment Variables for Secret Key
	if os.Getenv("VSCAN_SECRET_KEY") == "" {
		logging.VulscanoLog("fatal",
			"Missing Environment Variable for Data encryption secret key ",
			"VSCAN_SECRET_KEY")
	}

	// Create a certificate pool from the system certificate authority
	certPool, _ := x509.SystemCertPool()

	var err error

	//dbConnectConfig := pgconn.Config{
	//	Host: os.Getenv("VULSCANO_DB_HOST"),
	//	TLSConfig: &tls.Config{
	//		ServerName: os.Getenv("VULSCANO_DB_HOST"),
	//		RootCAs:    certPool,
	//	},
	//	User:     os.Getenv("VULSCANO_DB_USERNAME"),
	//	Password: os.Getenv("VULSCANO_DB_PASSWORD"),
	//	Database: os.Getenv("VULSCANO_DB_DATABASE_NAME"),
	//	DialFunc: (&net.Dialer{
	//		KeepAlive: 30 * time.Second,
	//		Timeout:   10 * time.Second,
	//	}).DialContext,
	//	// TargetSessionAttrs: "read-write",
	//}

	// pgx v4 requires config struct to be generated using ParseConfig method
	poolConfig, errParsePool := pgxpool.ParseConfig("")

	if errParsePool != nil {
		logging.VulscanoLog("fatal", fmt.Sprintf("failed to parse DB pool config %v", errParsePool))
	}

	//connPoolConfig = pgxpool.Config{
	//	ConnConfig: &pgx.ConnConfig{
	//		Config: dbConnectConfig,
	//	},
	//	MaxConns: 50,
	//}

	// Set Connection Parameters
	poolConfig.MaxConns = 50
	poolConfig.HealthCheckPeriod = 1 * time.Second
	poolConfig.ConnConfig.Host = os.Getenv("VULSCANO_DB_HOST")
	poolConfig.ConnConfig.User = os.Getenv("VULSCANO_DB_USERNAME")
	poolConfig.ConnConfig.Password = os.Getenv("VULSCANO_DB_PASSWORD")
	poolConfig.ConnConfig.Database = os.Getenv("VULSCANO_DB_DATABASE_NAME")

	poolConfig.ConnConfig.TLSConfig =
		&tls.Config{
			ServerName: os.Getenv("VULSCANO_DB_HOST"),
			RootCAs:    certPool,
		}

	poolConfig.ConnConfig.DialFunc =
		(&net.Dialer{
			KeepAlive: 30 * time.Second,
			Timeout:   10 * time.Second,
		}).DialContext

	// poolConfig.ConnConfig = &pgx.ConnConfig{Config: dbConnectConfig}

	ConnPool, err = pgxpool.ConnectConfig(context.Background(), poolConfig)

	if err != nil {
		logging.VulscanoLog(
			"fatal",
			"Unable to Create Postgres Connection Pool: ",
			err.Error())
	} else {
		logging.VulscanoLog("info", "Database Connection Pool successfully created")
	}

	// Instantiate DB object after successful connection
	DBInstance = newDBPool(ConnPool)

	postgresVersion := DBInstance.displayPostgresVersion()

	logging.VulscanoLog("info", "Postgres SQL Version: ", postgresVersion)

}

func newDBPool(pool *pgxpool.Pool) *vulscanoDB {

	return &vulscanoDB{
		db: pool,
	}
}

func (p *vulscanoDB) displayPostgresVersion() string {
	var version string

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	defer cancelQuery()

	err := p.db.QueryRow(ctxTimeout, "SELECT version()").Scan(&version)

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to retrieve Postgres Version: ",
			err.Error())
	}

	return version

}

// normalizeString is a helper function that converts empty string to nil pointer.
// Main usage is to convert empty string to Postgres NULL type
func normalizeString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
