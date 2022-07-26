// Package recordoutput writes dump records.
package recordoutput

import (
	"io"

	"github.com/yoursunny/ndn6dump"
)

// RecordOutput represents an output stream.
type RecordOutput interface {
	io.Closer
	Write(rec ndn6dump.Record) error
}
