//go:build embedsqlite

package server

import (
	"github.com/nnstd/glauth/v2/pkg/handler"
)

func NewEmbed(opts ...handler.Option) (handler.Handler, error) {
	return sqlite.NewSQLiteHandler(opts...), nil
}
