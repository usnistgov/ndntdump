# ndntdump NDN Traffic Dumper

**ndntdump** is a Go program that captures Named Data Networking network traffic.
It can perform online processing including address anonymization for privacy protection and NDN packet name extraction.

[![NDNgo logo](https://cdn.jsdelivr.net/gh/usnistgov/ndn-dpdk@7ebd6ec90a34d5e52b6860f16317500bca0c1ae6/docs/NDNgo-logo.svg)](https://github.com/usnistgov/ndn-dpdk/tree/main/ndn)

This software is developed at the [Smart Connected Systems Division](https://www.nist.gov/ctl/smart-connected-systems-division) of the [National Institute of Standards and Technology](https://www.nist.gov/).
It is in beta stage and will continue to be updated.

## Installation

This program is written in Go.
You can compile and install this program with:

```bash
go install github.com/usnistgov/ndntdump/cmd/ndntdump@latest
```

This program is also available as a Docker container:

```bash
docker build -t localhost/ndntdump 'github.com/usnistgov/ndntdump#main'
```

## Capture Modes

ndntdump can either live-capture from a network interface via AF\_PACKET socket, or read from a tcpdump trace file.
In both cases, it only recognizes Ethernet link mode.

To live-capture, set the network interface name in `--ifname` flag.
If the NDN forwarder is running in a Docker container, you must run ndntdump in the same network namespace as the forwarder, and specify the network interface name inside that network namespace.
It's possible to capture from all network interfaces with `--ifname '*'` flag; however, the network interface information isn't carried over to the output files.
To stop a live capture session, send SIGINT to the ndntdump process.

To read from a tcpdump trace file, set the filename in `--input` flag and set the local MAC address in `--local` flag.
This mode can recognize `.pcap` `.pcap.gz` `.pcap.zst` `.pcapng` `.pcapng.gz` `.pcapng.zst` file formats.
The local MAC address is necessary for determining traffic direction.

TCP flows with either source or destination port matching `--wss-port` flag (defaults to 9696) are analyzed for NDN over WebSocket traffic.
In live-capture mode, if the NDN forwarder and the HTTP server that performs TLS termination are communicating over `lo` interface, you must capture from this network interface by either running an additional ndntdump instance or using the `--ifname '*'` flag.

TCP flows with either source or destination port matching `--tcp-port` flag (defaults to 6363) are considered as NDN over TCP traffic.
These packets are anonymized and included in the output packets file.
However, this program cannot analyze NDN over TCP traffic, so that packet names and other properties do not appear in the output records file.

## Output Files

ndntdump emits two output files.

The **packets** file is a [pcapng](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/) file.
It contains Ethernet packets that carry NDN traffic.
Address anonymization has been performed on these packets.
When feasible, NDN packet payload, including Interest ApplicationParameters and Data Content, is zeroized, so that the output can be compressed effectively.
Payload blanking may be disabled with `--keep-payload` flag.

The **records** file is a [Newline delimited JSON (NDJSON)](https://github.com/ndjson/ndjson-spec) file.
Each line in this file is a JSON object that describes a NDN packet, either layer 2 or layer 3.
See [record.go](record.go) for the definition of property keys.
All information in the records file should be available by re-parsing the packets file.

Set output filenames in `--pcapng` and `--json` flags.
If the filename ends with `.gz` or `.zst`, the output file is compressed.

To rotate output files, send SIGHUP to the ndntdump process.
Upon receiving this signal, ndntdump closes and reopens each output file.
This may be used with [logrotate](https://man7.org/linux/man-pages/man8/logrotate.8.html)'s `postrotate` option.

## Address Anonymization

To ensure privacy compliance, ndntdump anonymizes IP and MAC addresses before output files are written.
IPv4 address keeps its leading 24 bits; IPv6 address keeps its leading 48 bits; MAC address keeps its leading 24 bits.
Lower bits are XOR'ed with a random value, which is consistent in each run, so that the same original address yields the same anonymized address.
Notice that this is a very simple and limited anonymization procedure, and we will incorporate better anonymization techniques in the future.

For WebSocket traffic, HTTP request header `X-Forwarded-For` may contain full client address.
This address is anonymized by changing the lower bits to zeros.

All IP addresses are anonymized by default.
Set IP subnets that should not be anonymized in `--keep-ip` flag (repeatable).
This may be set to subnets used by the network routers, to make it easier to identify router-to-router traffic.
A side effect is that it would expose non-router IP addresses within the same subnets.

MAC address anonymization is enabled by default.
It can be disabled with `--keep-mac` flag.
