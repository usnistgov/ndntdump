// Package fileoutput saves captured NDN trafic to files.
package fileoutput

import (
	"errors"

	"github.com/usnistgov/ndntdump"
)

// Open creates RecordOutput that writes to ndjson and pcapng files.
func Open(ndjsonFilename, pcapngFilename string) (ro ndntdump.RecordOutput, e error) {
	o := make(sliceOutput, 0, 2)

	if ndjsonFilename != "" {
		ndjson, e := NewLogrotateOutput(ndjsonFilename, NewNdjsonOutput)
		if e != nil {
			o.Close()
			return nil, e
		}
		o = append(o, ndjson)
	}

	if pcapngFilename != "" {
		pcapng, e := NewLogrotateOutput(pcapngFilename, NewPcapngOutput)
		if e != nil {
			o.Close()
			return nil, e
		}
		o = append(o, pcapng)
	}

	return o, nil
}

type sliceOutput []ndntdump.RecordOutput

func (o sliceOutput) Close() error {
	errs := make([]error, len(o))
	for i, output := range o {
		errs[i] = output.Close()
	}
	return errors.Join(errs...)
}

func (o sliceOutput) Write(rec ndntdump.Record) error {
	errs := make([]error, len(o))
	for i, output := range o {
		errs[i] = output.Write(rec)
	}
	return errors.Join(errs...)
}
