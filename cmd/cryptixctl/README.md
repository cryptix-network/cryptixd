# cryptixctl

cryptixctl is an RPC client for cryptixd

## Requirements

Go 1.23 or later.

## Installation

#### Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Ensure Go was installed properly and is a supported version:

```bash
$ go version
```

- Run the following commands to obtain and install cryptixd including all dependencies:

```bash
$ git clone https://github.com/cryptix-network/cryptixd
$ cd cryptixd/cmd/cryptixctl
$ go install .
```

- Cryptixctl should now be installed in `$(go env GOPATH)/bin`. If you did not already add the bin directory to your
  system path during Go installation, you are encouraged to do so now.

## Usage

The full cytxpctl configuration options can be seen with:

```bash
$ cytxpctl --help
```

But the minimum configuration needed to run it is:

```bash
$ cryptixctl <REQUEST_JSON>
```

For example:

```
$ cryptixctl '{"getBlockDagInfoRequest":{}}'
```

For a list of all available requests check out the [RPC documentation](infrastructure/network/netadapter/server/grpcserver/protowire/rpc.md)
