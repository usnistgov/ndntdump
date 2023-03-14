package fileoutput

import (
	"encoding/json"

	"github.com/usnistgov/ndntdump"
)

// NdjsonOutput saves packet information in Newline delimited JSON (NDJSON) file.
type NdjsonOutput struct {
	cf  *compressedFile
	enc *json.Encoder
}

func (o *NdjsonOutput) Close() error {
	return o.cf.Close()
}

func (o *NdjsonOutput) Write(rec ndntdump.Record) error {
	if len(rec.DirType) == 0 {
		return nil
	}
	return o.enc.Encode(rec)
}

// NewNdjsonOutput creates NdjsonOutput.
func NewNdjsonOutput(filename string) (o *NdjsonOutput, e error) {
	o = &NdjsonOutput{}
	if o.cf, e = newCompressedFile(filename); e != nil {
		return nil, e
	}
	o.enc = json.NewEncoder(o.cf)
	return o, nil
}
