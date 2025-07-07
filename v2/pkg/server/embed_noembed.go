//go:build !(embedsqlite || embedmysql)

package server

import (
	"errors"

	"github.com/nnstd/glauth/v2/pkg/handler"
)

func NewEmbed(opts ...handler.Option) (handler.Handler, error) {
	return nil, errors.New("GLAuth no longer supports plugins - database support is now embedded directly in the main binary")
}
