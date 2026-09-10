//nolint:revive
package gssapi_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/otuschhoff/gssapi"
	"github.com/go-logr/logr/testr"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func environmentVariables(t *testing.T) (string, string, string, string, string) {
	t.Helper()

	var (
		host     string
		realm    string
		username string
		password string
		keytab   string
		ok       bool
		err      error
	)

	for _, env := range []struct {
		ptr  *string
		name string
	}{
		{
			&host,
			"TEST_HOST",
		},
		{
			&realm,
			"TEST_REALM",
		},
		{
			&username,
			"TEST_USERNAME",
		},
		{
			&password,
			"TEST_PASSWORD",
		},
		{
			&keytab,
			"TEST_KEYTAB",
		},
	} {
		if *env.ptr, ok = os.LookupEnv(env.name); !ok {
			err = errors.Join(err, fmt.Errorf("%s is not set", env.name))
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	return host, realm, username, password, keytab
}

//nolint:cyclop,funlen,lll
func testExchange(t *testing.T, service string, mutual bool, initiatorOptions []Option[Initiator], acceptorOptions []Option[Acceptor]) {
	t.Helper()

	flags := gssapi.ContextFlagInteg | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence
	if mutual {
		flags |= gssapi.ContextFlagMutual
	}

	c, err := NewInitiator(initiatorOptions...)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = c.Close()
	}()

	s, err := NewAcceptor(acceptorOptions...)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = s.Close()
	}()

	output, cont, err := c.Initiate(service, flags, nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, len(output), 0)
	assert.True(t, cont)
	assert.WithinRange(t, c.Expiry(), time.Now().Add(1439*time.Minute), time.Now().Add(1441*time.Minute))

	input, cont, err := s.Accept(output)
	if err != nil {
		t.Fatal(err)
	}

	if mutual {
		assert.False(t, c.Established())
		assert.Greater(t, len(input), 0)
	} else {
		assert.True(t, c.Established())
		assert.Equal(t, len(input), 0)
	}

	assert.False(t, cont)
	assert.True(t, s.Established())
	assert.WithinRange(t, s.Expiry(), time.Now().Add(1439*time.Minute), time.Now().Add(1441*time.Minute))

	if mutual {
		output, cont, err = c.Initiate(service, flags, input)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, len(output), 0)
		assert.False(t, cont)
		assert.True(t, c.Established())
	}

	message := []byte("test message")

	signature, err := c.MakeSignature(message)
	if err != nil {
		t.Fatal(err)
	}

	if err = s.VerifySignature(message, signature); err != nil {
		t.Fatal(err)
	}

	signature, err = s.MakeSignature(message)
	if err != nil {
		t.Fatal(err)
	}

	if err = c.VerifySignature(message, signature); err != nil {
		t.Fatal(err)
	}
}

//nolint:funlen
func TestExchange(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	logger := testr.New(t)

	host, realm, username, password, keytab := environmentVariables(t)

	service := "host/" + host
	principal := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, service)

	config, err := os.ReadFile(filepath.Join("testdata", "krb5.conf"))
	if err != nil {
		t.Fatal(err)
	}

	tables := []struct {
		name             string
		mutual           bool
		initiatorOptions []Option[Initiator]
		acceptorOptions  []Option[Acceptor]
	}{
		{
			"session",
			false,
			[]Option[Initiator]{
				WithLogger[Initiator](logger),
				WithConfig(string(config)),
			},
			[]Option[Acceptor]{
				WithLogger[Acceptor](logger),
				WithServicePrincipal(&principal),
				WithClockSkew(5 * time.Second),
			},
		},
		{
			"mutual",
			true,
			[]Option[Initiator]{
				WithLogger[Initiator](logger),
				WithConfig(string(config)),
			},
			[]Option[Acceptor]{
				WithLogger[Acceptor](logger),
				WithServicePrincipal(&principal),
				WithClockSkew(5 * time.Second),
			},
		},
		{
			"password",
			true,
			[]Option[Initiator]{
				WithLogger[Initiator](logger),
				WithRealm(realm),
				WithUsername(username),
				WithPassword(password),
			},
			[]Option[Acceptor]{
				WithLogger[Acceptor](logger),
				WithServicePrincipal(&principal),
				WithClockSkew(5 * time.Second),
			},
		},
		{
			"keytab",
			true,
			[]Option[Initiator]{
				WithLogger[Initiator](logger),
				WithRealm(realm),
				WithUsername(username),
				WithKeytab[Initiator](keytab),
			},
			[]Option[Acceptor]{
				WithLogger[Acceptor](logger),
				WithServicePrincipal(&principal),
				WithClockSkew(5 * time.Second),
			},
		},
		{
			"keytab2",
			true,
			[]Option[Initiator]{
				WithLogger[Initiator](logger),
				WithRealm(realm),
				WithUsername(username),
				WithKeytab[Initiator](""),
			},
			[]Option[Acceptor]{
				WithLogger[Acceptor](logger),
				WithServicePrincipal(&principal),
				WithClockSkew(5 * time.Second),
			},
		},
	}

	for _, table := range tables {
		table := table
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			testExchange(t, service, table.mutual, table.initiatorOptions, table.acceptorOptions)
		})
	}
}
