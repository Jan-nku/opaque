// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/Jan-nku/opaque/internal"
	"github.com/Jan-nku/opaque/internal/ake"
	"github.com/Jan-nku/opaque/internal/encoding"
	"github.com/Jan-nku/opaque/internal/keyrecovery"
	"github.com/Jan-nku/opaque/internal/masking"
	"github.com/Jan-nku/opaque/internal/oprf"
	"github.com/Jan-nku/opaque/internal/tag"
	"github.com/Jan-nku/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errKe1Missing happens when LoginFinish is called and the client has no Ke1 in state.
	errKe1Missing = errors.New("missing KE1 in client state")
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Deserialize *Deserializer
	OPRF        *oprf.Client
	Ake         *ake.Client
	conf        *internal.Configuration
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(c *Configuration) (*Client, error) {
	if c == nil {
		c = DefaultConfiguration()
	}

	conf, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	return &Client{
		OPRF:        conf.OPRF.Client(),
		Ake:         ake.NewClient(),
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
	}, nil
}

// GetConf returns the internal configuration.
func (c *Client) GetConf() *internal.Configuration {
	return c.conf
}

// TODO: buildPRK
// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *group.Element) []byte {
	//output = h(pw, h'(pw)^ku) []byte
	output := c.OPRF.Finalize(evaluation)
	// Harden函数做一个延展？
	stretched := c.conf.KSF.Harden(output, nil, c.conf.OPRF.Group().ElementLength())
	//Extract
	return c.conf.KDF.Extract(nil, encoding.Concat(output, stretched))
}

// ClientRegistrationInitOptions enables setting internal client values for the client registration.
type ClientRegistrationInitOptions struct {
	// OPRFBlind: optional
	OPRFBlind *group.Scalar
}

func getClientRegistrationInitBlind(options []ClientRegistrationInitOptions) *group.Scalar {
	if len(options) == 0 {
		return nil
	}

	return options[0].OPRFBlind
}

// TODO: RegistrationInit
// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(
	password []byte,
	username []byte,
	options ...ClientRegistrationInitOptions,
) *message.RegistrationRequest {
	m := c.OPRF.Blind(password, getClientRegistrationInitBlind(options))

	return &message.RegistrationRequest{
		BlindedMessage: m,
		UserName:       username,
	}
}

// TODO: ClientRegistrationFinalizeOptions contain ClientIdentity, ServerIdentity
// ClientRegistrationFinalizeOptions enables setting optional client values for the client registration.
type ClientRegistrationFinalizeOptions struct {
	// ClientIdentity: optional
	ClientIdentity []byte
	// ServerIdentity: optional
	ServerIdentity []byte
	// EnvelopeNonce : optional
	EnvelopeNonce []byte
}

func initClientRegistrationFinalizeOptions(options []ClientRegistrationFinalizeOptions) *keyrecovery.Credentials {
	if len(options) == 0 {
		return &keyrecovery.Credentials{
			ClientIdentity: nil,
			ServerIdentity: nil,
			EnvelopeNonce:  nil,
		}
	}

	return &keyrecovery.Credentials{
		ClientIdentity: options[0].ClientIdentity,
		ServerIdentity: options[0].ServerIdentity,
		EnvelopeNonce:  options[0].EnvelopeNonce,
	}
}

// TODO: RegistrationFinalize
// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse.
func (c *Client) RegistrationFinalize(
	resp *message.RegistrationResponse,
	options ...ClientRegistrationFinalizeOptions,
) (record *message.RegistrationRecord, exportKey []byte) {
	credentials := initClientRegistrationFinalizeOptions(options)
	// generate randomizedPwd from resp.EvaluatedMessage， related to h(pw, h'(pw)^ku)
	randomizedPwd := c.buildPRK(resp.EvaluatedMessage)

	// generate maskingKey from hash(randomizedPwd)
	maskingKey := c.conf.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.conf.KDF.Size())
	envelope, clientPublicKey, exportKey := keyrecovery.Store(c.conf, randomizedPwd, resp.Pks, credentials)

	//envelope 存储 在 RegistrationRecord 中
	return &message.RegistrationRecord{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envelope.Serialize(),
	}, exportKey
}

// ClientLoginInitOptions enables setting optional values for the session, which default to secure random values if not
// set.
type ClientLoginInitOptions struct {
	// Blind: optional
	Blind *group.Scalar
	// EphemeralSecretKey: optional
	EphemeralSecretKey *group.Scalar
	// Nonce: optional
	Nonce []byte
	// NonceLength: optional
	NonceLength uint
}

func (c ClientLoginInitOptions) get() (*group.Scalar, ake.Options) {
	return c.Blind, ake.Options{
		EphemeralSecretKey: c.EphemeralSecretKey,
		Nonce:              c.Nonce,
		NonceLength:        c.NonceLength,
	}
}

func getClientLoginInitOptions(options []ClientLoginInitOptions) (*group.Scalar, ake.Options) {
	if len(options) != 0 {
		return options[0].get()
	}

	return nil, ake.Options{
		EphemeralSecretKey: nil,
		Nonce:              nil,
		NonceLength:        internal.NonceLength,
	}
}

// TODO: LoginInit(password)
// LoginInit initiates the authentication process, returning a KE1 message blinding the given password.
func (c *Client) LoginInit(password, username []byte, options ...ClientLoginInitOptions) *message.KE1 {
	blind, akeOptions := getClientLoginInitOptions(options)
	m := c.OPRF.Blind(password, blind)

	//TODO: start initiates the 3dh protocol, call setOptions(g, options) function
	ke1 := c.Ake.Start(c.conf.Group, akeOptions)
	ke1.CredentialRequest = message.NewCredentialRequest(c.conf.OPRF, m)
	ke1.UserName = make([]byte, len(username))
	copy(ke1.UserName, username)
	c.Ake.Ke1 = ke1.Serialize()

	return ke1
}

// ClientLoginFinishOptions enables setting optional client values for the client registration.
type ClientLoginFinishOptions struct {
	// ClientIdentity: optional
	ClientIdentity []byte
	// ServerIdentity: optional
	ServerIdentity []byte
}

func initClientLoginFinishOptions(options []ClientLoginFinishOptions) *ake.Identities {
	if len(options) == 0 {
		return &ake.Identities{
			ClientIdentity: nil,
			ServerIdentity: nil,
		}
	}

	return &ake.Identities{
		ClientIdentity: options[0].ClientIdentity,
		ServerIdentity: options[0].ServerIdentity,
	}
}

// LoginFinish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) LoginFinish(
	ke2 *message.KE2, options ...ClientLoginFinishOptions,
) (ke3 *message.KE3, exportKey []byte, err error) {
	if len(c.Ake.Ke1) == 0 {
		return nil, nil, errKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	identities := initClientLoginFinishOptions(options)

	// Finalize the OPRF.
	randomizedPwd := c.buildPRK(ke2.EvaluatedMessage)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPwd, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("unmasking: %w", err)
	}

	// Recover the client keys.
	clientSecretKey, clientPublicKey,
		exportKey, err := keyrecovery.Recover(
		c.conf,
		randomizedPwd,
		serverPublicKeyBytes,
		identities.ClientIdentity,
		identities.ServerIdentity,
		envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("key recovery: %w", err)
	}

	// Finalize the AKE.
	// SetIdentities sets the client and server identities to their respective public key if not set.
	identities.SetIdentities(clientPublicKey, serverPublicKeyBytes)

	// produce ke3
	ke3, err = c.Ake.Finalize(c.conf, identities, clientSecretKey, serverPublicKey, ke2)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing AKE: %w", err)
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to LoginFinish() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
