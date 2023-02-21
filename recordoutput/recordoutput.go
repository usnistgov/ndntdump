// Package recordoutput writes dump records.
package recordoutput

import (
	"io"

	"github.com/usnistgov/ndntdump"
)

// RecordOutput represents an output stream.
type RecordOutput interface {
	io.Closer
	Write(rec ndntdump.Record) error
}
