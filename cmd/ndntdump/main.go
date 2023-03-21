// Command ndntdump captures NDN traffic from a network interface.
package main

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"
	"github.com/usnistgov/ndntdump"
	"github.com/usnistgov/ndntdump/fileoutput"
	"github.com/usnistgov/ndntdump/pcapinput"
	"go4.org/netipx"
)

var (
	keepIPs *netipx.IPSet
	input   pcapinput.Handle
	reader  *ndntdump.Reader
	output  ndntdump.RecordOutput
)

var app = &cli.App{
	Name:  "ndntdump",
	Usage: "capture, anonymize, and analyze NDN traffic",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "ifname",
			Aliases: []string{"i"},
			Usage:   "network `interface` name",
		},
		&cli.StringFlag{
			Name:    "input",
			Aliases: []string{"r"},
			Usage:   "input `filename`",
		},
		&cli.StringFlag{
			Name:  "local",
			Usage: "local MAC `address`",
		},
		&cli.IntFlag{
			Name:  "tcp-port",
			Usage: "NDN over TCP `port`",
			Value: 6363,
		},
		&cli.IntFlag{
			Name:  "wss-port",
			Usage: "WebSocket server `port`",
			Value: 9696,
		},
		&cli.StringFlag{
			Name:    "pcapng",
			Aliases: []string{"w"},
			Usage:   ".pcapng.gz output `filename`",
		},
		&cli.StringFlag{
			Name:    "json",
			Aliases: []string{"L"},
			Usage:   ".json.gz output `filename`",
		},
		&cli.StringSliceFlag{
			Name:    "keep-ip",
			Aliases: []string{"N"},
			Usage:   "don't anonymize IP `prefix`",
		},
		&cli.BoolFlag{
			Name:  "keep-mac",
			Usage: "don't anonymize MAC addresses",
		},
	},
	Action: func(c *cli.Context) (e error) {
		if input, e = pcapinput.Open(c.String("ifname"), c.String("input"), c.String("local")); e != nil {
			return cli.Exit(e, 1)
		}
		if keepIPs, e = ndntdump.ParseIPSet(c.StringSlice("keep-ip")); e != nil {
			return cli.Exit(e, 1)
		}
		reader = ndntdump.NewReader(input, ndntdump.ReaderOptions{
			IsLocal:       input.IsLocal,
			TCPPort:       c.Int("tcp-port"),
			WebSocketPort: c.Int("wss-port"),
			Anonymizer:    ndntdump.NewAnonymizer(keepIPs, c.Bool("keep-mac")),
		})

		if output, e = fileoutput.Open(c.String("json"), c.String("pcapng")); e != nil {
			return cli.Exit(e, 1)
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		go func() {
			<-sig
			input.Close()
		}()

		for {
			rec, e := reader.Read()
			if e != nil {
				if errors.Is(e, io.EOF) {
					return nil
				}
				return cli.Exit(e, 1)
			}

			e = output.Write(rec)
			if e != nil {
				return cli.Exit(e, 1)
			}
		}
	},
	After: func(c *cli.Context) error {
		if input != nil {
			input.Close()
		}
		if output != nil {
			output.Close()
		}
		return nil
	},
}

func main() {
	app.Run(os.Args)
}
