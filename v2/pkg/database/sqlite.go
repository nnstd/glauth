package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nnstd/glauth/v2/pkg/handler"
)

type SqliteBackend struct {
}

func NewSQLiteHandler(opts ...handler.Option) handler.Handler {
	backend := SqliteBackend{}
	return NewDatabaseHandler(backend, opts...)
}

func (b SqliteBackend) GetDriverName() string {
	return "sqlite3"
}

func (b SqliteBackend) GetPrepareSymbol() string {
	return "?"
}

// Create db/schema if necessary
func (b SqliteBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups TEXT DEFAULT '',
	givenname TEXT DEFAULT '',
	sn TEXT DEFAULT '',
	mail TEXT DEFAULT '',
	loginshell TEXT DEFAULT '',
	homedirectory TEXT DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 TEXT DEFAULT '',
	passbcrypt TEXT DEFAULT '',
	otpsecret TEXT DEFAULT '',
	yubikey TEXT DEFAULT '',
	sshkeys TEXT DEFAULT '',
	custattr TEXT DEFAULT '{}')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name on users(name)")
	statement.Exec()
	// Add case-insensitive indexes for better performance
	statement, _ = db.Prepare("CREATE INDEX IF NOT EXISTS idx_user_name_lower on users(lower(name))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE INDEX IF NOT EXISTS idx_user_mail_lower on users(lower(mail))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS ldapgroups (id INTEGER PRIMARY KEY, name TEXT NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on ldapgroups(name)")
	statement.Exec()
	// Add case-insensitive index for groups
	statement, _ = db.Prepare("CREATE INDEX IF NOT EXISTS idx_group_name_lower on ldapgroups(lower(name))")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id INTEGER PRIMARY KEY, userid INTEGER NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL)")
	statement.Exec()
	// Add index for capabilities table to optimize JOIN queries
	statement, _ = db.Prepare("CREATE INDEX IF NOT EXISTS idx_capabilities_userid on capabilities(userid)")
	statement.Exec()
}

// Migrate schema if necessary
func (b SqliteBackend) MigrateSchema(db *sql.DB, checker func(*sql.DB, string, string) bool) {
	if !checker(db, "users", "sshkeys") {
		statement, _ := db.Prepare("ALTER TABLE users ADD COLUMN sshkeys TEXT DEFAULT ''")
		statement.Exec()
	}
	if checker(db, "groups", "name") {
		statement, _ := db.Prepare("DROP TABLE ldapgroups")
		statement.Exec()
		statement, _ = db.Prepare("ALTER TABLE groups RENAME TO ldapgroups")
		statement.Exec()
	}
}
