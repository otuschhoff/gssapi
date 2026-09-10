[![GitHub release](https://img.shields.io/github/v/release/bodgit/gssapi)](https://github.com/otuschhoff/gssapi/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bodgit/gssapi/build.yml?branch=main)](https://github.com/otuschhoff/gssapi/actions?query=workflow%3ABuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/gssapi/badge.svg?branch=main)](https://coveralls.io/github/bodgit/gssapi?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/otuschhoff/gssapi)](https://goreportcard.com/report/github.com/otuschhoff/gssapi)
[![GoDoc](https://godoc.org/github.com/otuschhoff/gssapi?status.svg)](https://godoc.org/github.com/otuschhoff/gssapi)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/bodgit/gssapi)

# GSSAPI wrapper for gokrb5

The [github.com/otuschhoff/gssapi](https://godoc.org/github.com/otuschhoff/gssapi)
package implements a GSSAPI-like wrapper around the
[github.com/jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) package.

Sample Initiator (Client):

```golang
package main

import (
	. "github.com/otuschhoff/gssapi"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

func main() {
	initiator, err := NewInitiator(WithRealm("EXAMPLE.COM"), WithUsername("test"), WithKeytab[Initiator]("test.keytab"))
	if err != nil {
		panic(err)
	}

	defer initiator.Close()

	output, cont, err := initiator.Initiate("host/ssh.example.com", gssapi.ContextFlagInteg|gssapi.ContextFlagMutual, nil)
	if err != nil {
		panic(err)
	}

	// transmit output to Acceptor

	signature, err := initiator.MakeSignature(message)
	if err != nil {
		panic(err)
	}

	// transmit message and signature to Acceptor
}
```

Sample Acceptor (Server):

```golang
package main

import (
	. "github.com/otuschhoff/gssapi"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func main() {
	principal := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/ssh.example.com")

	acceptor, err := NewAcceptor(WithServicePrincipal(&principal))
	if err != nil {
		panic(err)
	}

	defer acceptor.Close()

	// receive input from Initiator

	output, cont, err := acceptor.Accept(input)
	if err != nil {
		panic(err)
	}

	// transmit output back to Initiator

	// receive message and signature from Initiator

	if err := acceptor.VerifySignature(message, signature); err != nil {
		panic(err)
	}
}
```
