
Cryptixd
====

[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://choosealicense.com/licenses/isc/)

Cryptixd is the reference full node Cryptix implementation written in Go (golang).

## What is cryptix

Cryptix is an attempt at a proof-of-work cryptocurrency with instant confirmations and sub-second block times. It is based on [the PHANTOM protocol](https://eprint.iacr.org/2018/104.pdf), a generalization of Nakamoto consensus.

## Requirements

Go 1.18 or later.

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
$ cd cryptixd
$ go install . ./cmd/...
```

- Cryptixd (and utilities) should now be installed in `$(go env GOPATH)/bin`. If you did
  not already add the bin directory to your system path during Go installation,
  you are encouraged to do so now.


## Getting Started

Cryptixd has several configuration options available to tweak how it runs, but all
of the basic operations work with zero configuration.

```bash
$ cryptixd
```

## Discord
Soon

## Issue Tracker

The [integrated github issue tracker](https://github.com/cryptix-network/cryptixd/issues)
is used for this project.

Issue priorities may be seen at https://github.com/orgs/cryptix-network/projects/4

## Documentation

The [documentation](https://github.com/cryptix-network/docs) is a work-in-progress

## License

Cryptixd is licensed under the copyfree [ISC License](https://choosealicense.com/licenses/isc/).