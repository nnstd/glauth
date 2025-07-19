package database

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"github.com/nnstd/glauth/v2/pkg/handler"
)

type MysqlBackend struct {
}

func NewMySQLHandler(opts ...handler.Option) handler.Handler {
	backend := MysqlBackend{}
	return NewDatabaseHandler(backend, opts...)
}

func (b MysqlBackend) GetDriverName() string {
	return "mysql"
}

func (b MysqlBackend) GetPrepareSymbol() string {
	return "?"
}

// Create db/schema if necessary
func (b MysqlBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(64) NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups VARCHAR(1024) DEFAULT '',
	givenname VARCHAR(64) DEFAULT '',
	sn VARCHAR(64) DEFAULT '',
	mail VARCHAR(254) DEFAULT '',
	loginshell VARCHAR(64) DEFAULT '',
	homedirectory VARCHAR(64) DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 VARCHAR(64) DEFAULT '',
	passbcrypt VARCHAR(64) DEFAULT '',
	otpsecret VARCHAR(64) DEFAULT '',
	yubikey VARCHAR(128) DEFAULT '',
	sshkeys TEXT DEFAULT '',
	custattr TEXT DEFAULT '{}')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_user_name on users(name)")
	statement.Exec()
	// Add case-insensitive indexes for better performance
	statement, _ = db.Prepare("CREATE INDEX idx_user_name_lower on users(lower(name))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE INDEX idx_user_mail_lower on users(lower(mail))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS ldapgroups (id INTEGER AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64) NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_group_name on ldapgroups(name)")
	statement.Exec()
	// Add case-insensitive index for groups
	statement, _ = db.Prepare("CREATE INDEX idx_group_name_lower on ldapgroups(lower(name))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER AUTO_INCREMENT PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id INTEGER AUTO_INCREMENT PRIMARY KEY, userid INTEGER NOT NULL, action VARCHAR(128) NOT NULL, object VARCHAR(128) NOT NULL)")
	statement.Exec()
	// Add index for capabilities table to optimize JOIN queries
	statement, _ = db.Prepare("CREATE INDEX idx_capabilities_userid on capabilities(userid)")
	statement.Exec()
}

// Migrate schema if necessary
func (b MysqlBackend) MigrateSchema(db *sql.DB, checker func(*sql.DB, string, string) bool) {
	if !checker(db, "users", "sshkeys") {
		statement, _ := db.Prepare("ALTER TABLE users ADD COLUMN sshkeys TEXT DEFAULT ''")
		statement.Exec()
	}
	if checker(db, "groups", "name") {
		statement, _ := db.Prepare("DROP TABLE ldapgroups")
		statement.Exec()
		statement, _ = db.Prepare("ALTER TABLE groups RENAME ldapgroups")
		statement.Exec()
	}
}
