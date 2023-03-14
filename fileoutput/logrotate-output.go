package fileoutput

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/usnistgov/ndntdump"
)

// LogrotateOutput wraps a file-based RecordOutput to reopen the file upon SIGHUP.
type LogrotateOutput[T ndntdump.RecordOutput] struct {
	filename string
	mu       sync.Mutex
	sighup   chan os.Signal
	output   T
	create   func(string) (T, error)
}

func (o *LogrotateOutput[T]) reopen(first bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	output, e := o.create(o.filename)
	if e != nil {
		return e
	}

	if !first {
		o.output.Close()
	}
	o.output = output
	return nil
}

func (o *LogrotateOutput[T]) Close() error {
	signal.Stop(o.sighup)
	close(o.sighup)
	return o.output.Close()
}

func (o *LogrotateOutput[T]) Write(rec ndntdump.Record) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.output.Write(rec)
}

// NewLogrotateOutput creates LogrotateOutput.
func NewLogrotateOutput[T ndntdump.RecordOutput](filename string, create func(string) (T, error)) (o *LogrotateOutput[T], e error) {
	o = &LogrotateOutput[T]{
		filename: filename,
		sighup:   make(chan os.Signal, 1),
		create:   create,
	}
	if e = o.reopen(true); e != nil {
		return nil, e
	}

	signal.Notify(o.sighup, syscall.SIGHUP)
	go func() {
		for range o.sighup {
			o.reopen(false)
		}
	}()

	return o, nil
}
