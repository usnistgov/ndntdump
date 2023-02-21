# ndntdump NDN Traffic Dumper

**ndntdump** is a Go program that captures Named Data Networking network traffic.
It can perform online processing including IP anonymization for privacy protection and NDN packet name extraction.

[![NDNgo logo](https://cdn.jsdelivr.net/gh/usnistgov/ndn-dpdk@7ebd6ec90a34d5e52b6860f16317500bca0c1ae6/docs/NDNgo-logo.svg)](https://github.com/usnistgov/ndn-dpdk/tree/main/ndn)

This software is developed at the [Smart Connected Systems Division](https://www.nist.gov/ctl/smart-connected-systems-division) of the [National Institute of Standards and Technology](https://www.nist.gov/).
It is in beta stage and will continue to be updated.

## Installation

This program is written in Go.
It requires both Go compiler and C compiler.
You can compile and install this program with:

```bash
go install github.com/usnistgov/ndntdump/cmd/ndntdump@latest
```

This program is also available as a Docker container:

```bash
docker build -t ndntdump 'github.com/usnistgov/ndntdump#main'
```

## Capture Modes

ndntdump can either live-capture from a network interface via AF\_PACKET socket, or read from a tcpdump trace file.
In both cases, it only recognizes Ethernet link mode.

To live-capture, set the network interface name in `--ifname` flag.
If the NDN forwarder is running in a Docker container, you must run ndntdump in the same network namespace as the forwarder, and specify the network interface name inside that network namespace.
To capture WebSocket traffic, if the NDN forwarder and the HTTP server that performs TLS termination are communicating over `lo` interface, you must run an additional ndntdump instance to capture from this interface.
To stop a live capture session, send SIGINT to the ndntdump process.

To read from a tcpdump trace file, set the filename in `--input` flag and set the local MAC address in `--local` flag.
This mode can recognize `.pcap` `.pcap.gz` `.pcap.zst` `.pcapng` `.pcapng.gz` `.pcapng.zst` file formats.
The local MAC address is necessary for determining traffic direction.

## Output Files

ndntdump emits two output files.

The **packets** file is a [pcapng](https://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng/) file.
It contains Ethernet packets that carry NDN traffic.
IP anonymization has been performed on these packets.
When feasible, NDN packet payload, including Interest ApplicationParameters and Data Content, is zeroized, so that the output can be compressed effectively.

The **records** file is a [Newline delimited JSON (NDJSON)](https://github.com/ndjson/ndjson-spec) file.
Each line in this file is a JSON object that describes a NDN packet, either layer 2 or layer 3.
See [record.go](record.go) for the definition of property keys.
All information in the records file should be available by re-parsing the packets file.

Set output filenames in `--pcapng` and `--json` flags.
If the filename ends with `.gz` or `.zst`, the output file is compressed.

## IP Anonymization

To ensure privacy compliance, ndntdump performs IP anonymization before output files are written.
IPv4 address keeps its leading 24 bits; IPv6 address keeps its leading 48 bits.
Lower bits are XOR'ed with a random value, which is consistent in each run, so that the same original address yields the same anonymized address.

For WebSocket traffic, HTTP request header `X-Forwarded-For` may contain full client address.
This address is anonymized by changing the lower bits to zeros.

Set IP subnets that should not be anonymized in `--keep-ip` flag (repeatable).
This should be set to subnets used by the network routers, so that it is easier to identify router-to-router traffic.
A side effect is that it would expose non-router IP addresses within the same subnets.
