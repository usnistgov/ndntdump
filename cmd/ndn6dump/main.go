// Command ndn6dump captures NDN traffic from a network interface.
package main

import (
	"errors"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/yoursunny/ndn6dump"
	"github.com/yoursunny/ndn6dump/pcapinput"
	"github.com/yoursunny/ndn6dump/recordoutput"
	"inet.af/netaddr"
)

var (
	keepIPs *netaddr.IPSet
	input   pcapinput.Handle
	reader  *ndn6dump.Reader
	output  recordoutput.RecordOutput
)

var app = &cli.App{
	Name:  "ndn6dump",
	Usage: "capture, anonymize, and analyze NDN traffic",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "ifname",
			Aliases: []string{"i"},
			Usage:   "network interface name",
		},
		&cli.StringFlag{
			Name:    "input",
			Aliases: []string{"r"},
			Usage:   "input filename",
		},
		&cli.StringFlag{
			Name:  "local",
			Usage: "local MAC address",
		},
		&cli.StringFlag{
			Name:    "pcapng",
			Aliases: []string{"w"},
			Usage:   ".pcapng.gz output filename",
		},
		&cli.StringFlag{
			Name:    "json",
			Aliases: []string{"L"},
			Usage:   ".json.gz output filename",
		},
		&cli.StringSliceFlag{
			Name:    "keep-ip",
			Aliases: []string{"N"},
			Usage:   "don't anonymize IP prefix",
		},
	},
	Action: func(c *cli.Context) (e error) {
		if input, e = pcapinput.Open(c.String("ifname"), c.String("input"), c.String("local")); e != nil {
			return cli.Exit(e, 1)
		}
		if keepIPs, e = ndn6dump.ParseIPSet(c.StringSlice("keep-ip")); e != nil {
			return cli.Exit(e, 1)
		}
		reader = ndn6dump.NewReader(input, input.LocalMAC(), ndn6dump.NewIPAnonymizer(keepIPs))

		if output, e = recordoutput.OpenFiles(input.Name(), c.String("json"), c.String("pcapng")); e != nil {
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
	rand.Seed(time.Now().UnixNano())
	app.Run(os.Args)
}
