package recordoutput

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/klauspost/compress/zstd"
	"github.com/usnistgov/ndntdump"
	"go.uber.org/multierr"
)

func createFileCompressed(filename string, file **os.File, compress *io.WriteCloser) (w io.Writer, e error) {
	if *file, e = os.Create(filename); e != nil {
		return nil, e
	}

	switch filepath.Ext(filename) {
	case ".gz":
		*compress, _ = gzip.NewWriterLevel(*file, gzip.BestSpeed)
		return *compress, nil
	case ".zst":
		*compress, _ = zstd.NewWriter(*file, zstd.WithEncoderLevel(zstd.SpeedDefault))
		return *compress, nil
	}

	return *file, nil
}

// OpenFiles creates RecordOutput that writes to files.
func OpenFiles(ifname, ndjsonFilename, pcapngFilename string) (ro RecordOutput, e error) {
	if ndjsonFilename == "" && pcapngFilename == "" {
		return nil, errors.New("no output specified")
	}

	o := &filesOutput{}
	defer func() {
		if ro == nil {
			o.Close()
		}
	}()

	if ndjsonFilename != "" {
		w, e := createFileCompressed(ndjsonFilename, &o.ndjsonFile, &o.ndjsonCompress)
		if e != nil {
			return nil, e
		}
		o.ndjsonEncoder = json.NewEncoder(w)
		o.ndjsonEncoder.SetEscapeHTML(false)
	}

	if pcapngFilename != "" {
		w, e := createFileCompressed(pcapngFilename, &o.pcapngFile, &o.pcapngCompress)
		if e != nil {
			return nil, e
		}
		o.pcapngWriter, e = pcapgo.NewNgWriterInterface(w, pcapgo.NgInterface{
			Name:     ifname,
			LinkType: layers.LinkTypeEthernet,
		}, pcapgo.NgWriterOptions{
			SectionInfo: pcapgo.NgSectionInfo{
				Application: "ndntdump",
			},
		})
		if e != nil {
			return nil, e
		}
	}

	return o, nil
}

type filesOutput struct {
	ndjsonFile     *os.File
	ndjsonCompress io.WriteCloser
	ndjsonEncoder  *json.Encoder

	pcapngFile     *os.File
	pcapngCompress io.WriteCloser
	pcapngWriter   *pcapgo.NgWriter
}

func (o *filesOutput) Close() error {
	errs := []error{}

	if o.ndjsonCompress != nil {
		errs = append(errs, o.ndjsonCompress.Close())
	}
	if o.ndjsonFile != nil {
		errs = append(errs, o.ndjsonFile.Close())
	}

	if o.pcapngWriter != nil {
		errs = append(errs, o.pcapngWriter.Flush())
	}
	if o.pcapngCompress != nil {
		errs = append(errs, o.pcapngCompress.Close())
	}
	if o.pcapngFile != nil {
		errs = append(errs, o.pcapngFile.Close())
	}

	return multierr.Combine(errs...)
}

func (o *filesOutput) Write(rec ndntdump.Record) error {
	errs := []error{}
	if o.ndjsonEncoder != nil && len(rec.DirType) > 0 {
		errs = append(errs, o.ndjsonEncoder.Encode(rec))
	}
	if o.pcapngWriter != nil && len(rec.Wire) > 0 {
		rec.CaptureInfo.InterfaceIndex = 0
		rec.CaptureInfo.AncillaryData = nil
		errs = append(errs, o.pcapngWriter.WritePacket(rec.CaptureInfo, rec.Wire))
	}
	return multierr.Combine(errs...)
}
