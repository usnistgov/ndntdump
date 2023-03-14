package fileoutput

import (
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

type compressedFile struct {
	file     *os.File
	compress io.WriteCloser
	w        io.Writer
}

func (cf *compressedFile) Write(b []byte) (int, error) {
	return cf.w.Write(b)
}

func (cf *compressedFile) Close() error {
	cf.w = io.Discard
	errs := []error{}
	if cf.compress != nil {
		errs = append(errs, cf.compress.Close())
		cf.compress = nil
	}
	if cf.file != nil {
		errs = append(errs, cf.file.Close())
		cf.file = nil
	}
	return errors.Join(errs...)
}

func newCompressedFile(filename string) (cf *compressedFile, e error) {
	cf = &compressedFile{
		w: io.Discard,
	}

	if cf.file, e = os.Create(filename); e != nil {
		return nil, e
	}
	cf.w = cf.file

	switch filepath.Ext(filename) {
	case ".gz":
		cf.compress, _ = gzip.NewWriterLevel(cf.file, gzip.BestSpeed)
		cf.w = cf.compress
	case ".zst":
		cf.compress, _ = zstd.NewWriter(cf.file, zstd.WithEncoderLevel(zstd.SpeedDefault))
		cf.w = cf.compress
	}

	return cf, nil
}
