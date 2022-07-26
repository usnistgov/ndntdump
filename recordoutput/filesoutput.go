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
	"github.com/yoursunny/ndn6dump"
	"go.uber.org/multierr"
)

func createFileCompressed(filename string, file **os.File, compress **gzip.Writer) (w io.Writer, e error) {
	if *file, e = os.Create(filename); e != nil {
		return nil, e
	}

	if filepath.Ext(filename) == ".gz" {
		*compress, _ = gzip.NewWriterLevel(*file, gzip.BestSpeed)
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
				Application: "ndn6dump",
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
	ndjsonCompress *gzip.Writer
	ndjsonEncoder  *json.Encoder

	pcapngFile     *os.File
	pcapngCompress *gzip.Writer
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
		errs = append(errs, o.pcapngCompress.Flush())
	}
	if o.pcapngFile != nil {
		errs = append(errs, o.pcapngFile.Close())
	}

	return multierr.Combine(errs...)
}

func (o *filesOutput) Write(rec ndn6dump.Record) error {
	errs := []error{}
	if o.ndjsonEncoder != nil {
		errs = append(errs, o.ndjsonEncoder.Encode(rec))
	}
	if o.pcapngWriter != nil {
		errs = append(errs, o.pcapngWriter.WritePacket(rec.CaptureInfo, rec.Wire))
	}
	return multierr.Combine(errs...)
}
