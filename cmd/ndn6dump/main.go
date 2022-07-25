// Command ndn6dump captures NDN traffic from a network interface.
package main

import (
	"compress/gzip"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/urfave/cli/v2"
	"github.com/yoursunny/ndn6dump"
	"inet.af/netaddr"
)

var (
	netif   *net.Interface
	keepIPs *netaddr.IPSet
	handle  *afpacket.TPacket
	reader  *ndn6dump.Reader
	output  *os.File
	gzOut   *gzip.Writer
	writer  *pcapgo.NgWriter
)

var app = &cli.App{
	Name: "ndn6dump",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "ifname",
			Aliases:  []string{"i"},
			Usage:    "network interface name",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "output",
			Aliases:  []string{"w"},
			Usage:    "output filename",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:    "keep-ip",
			Aliases: []string{"N"},
			Usage:   "don't anonymize IP prefix",
		},
	},
	Before: func(c *cli.Context) (e error) {
		if netif, e = net.InterfaceByName(c.String("ifname")); e != nil {
			return cli.Exit(e, 1)
		}

		if keepIPs, e = ndn6dump.ParseIPSet(c.StringSlice("keep-ip")); e != nil {
			return cli.Exit(e, 1)
		}

		return nil
	},
	Action: func(c *cli.Context) (e error) {
		if handle, e = afpacket.NewTPacket(afpacket.OptInterface(netif.Name)); e != nil {
			return cli.Exit(e, 1)
		}
		reader = ndn6dump.NewReader(handle, ndn6dump.NewIPAnonymizer(keepIPs))

		if output, e = os.OpenFile(c.String("output"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666); e != nil {
			return cli.Exit(e, 1)
		}
		gzOut, _ = gzip.NewWriterLevel(output, gzip.BestSpeed)

		if writer, e = pcapgo.NewNgWriterInterface(gzOut, pcapgo.NgInterface{
			Name:     netif.Name,
			LinkType: layers.LinkTypeEthernet,
		}, pcapgo.NgWriterOptions{
			SectionInfo: pcapgo.NgSectionInfo{
				Application: "pcapgo",
			},
		}); e != nil {
			return cli.Exit(e, 1)
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT)
		defer signal.Stop(sig)

		for {
			select {
			case <-sig:
				return nil
			default:
			}

			rec, e := reader.Read()
			if e != nil {
				return cli.Exit(e, 1)
			}

			e = writer.WritePacket(rec.CaptureInfo, rec.Wire)
			if e != nil {
				return cli.Exit(e, 1)
			}
		}
	},
	After: func(c *cli.Context) error {
		if handle != nil {
			handle.Close()
		}
		if writer != nil {
			writer.Flush()
		}
		if gzOut != nil {
			gzOut.Close()
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
