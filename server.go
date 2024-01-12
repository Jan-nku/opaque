// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Jan-nku/opaque/internal/oprf"
	"net/http"
	"sync"

	group "github.com/bytemare/crypto"

	"github.com/Jan-nku/opaque/internal"
	"github.com/Jan-nku/opaque/internal/ake"
	"github.com/Jan-nku/opaque/internal/encoding"
	"github.com/Jan-nku/opaque/internal/masking"
	"github.com/Jan-nku/opaque/internal/tag"
	"github.com/Jan-nku/opaque/message"
)

var (
	// ErrNoServerKeyMaterial indicates that the server's key material has not been set.
	ErrNoServerKeyMaterial = errors.New("key material not set: call SetKeyMaterial() to set values")

	// ErrAkeInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

	// ErrInvalidState indicates that the given state is not valid due to a wrong length.
	ErrInvalidState = errors.New("invalid state length")

	// ErrInvalidEnvelopeLength indicates the envelope contained in the record is of invalid length.
	ErrInvalidEnvelopeLength = errors.New("record has invalid envelope length")

	// ErrInvalidPksLength indicates the input public key is not of right length.
	ErrInvalidPksLength = errors.New("input server public key's length is invalid")

	// ErrInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrInvalidOPRFSeedLength = errors.New("input OPRF seed length is invalid (must be of hash output length)")

	// ErrZeroSKS indicates that the server's private key is a zero scalar.
	ErrZeroSKS = errors.New("server private key is zero")
)

// Server represents an OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
	OPRF        *oprf.Server
	Ake         *ake.Server
	*keyMaterial
}

type keyMaterial struct {
	serverIdentity  []byte
	serverSecretKey *group.Scalar
	serverPublicKey []byte
	oprfSeed        []byte
	t1              *group.Element
	t2              *group.Element
	gs              *group.Element
}

// TODO: NewServer()
// NewServer returns a Server instantiation given the application Configuration.
func NewServer(c *Configuration) (*Server, error) {
	if c == nil {
		c = DefaultConfiguration()
	}

	conf, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	return &Server{
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
		OPRF:        conf.OPRF.Server(),
		Ake:         ake.NewServer(),
		keyMaterial: nil,
	}, nil
}

// GetConf return the internal configuration.
func (s *Server) GetConf() *internal.Configuration {
	return s.conf
}

// 客户端发送HTTP请求的函数
func (s *Server) httpResponse(url string, wg *sync.WaitGroup, resultChan chan<- *group.Element) {
	defer wg.Done()

	// 发送HTTPS GET请求
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("无法发送请求:", err)
	}
	defer response.Body.Close()

	// 检查响应的状态码
	if response.StatusCode != http.StatusOK {
		fmt.Println("请求失败，状态码:", response.StatusCode)
	}

	// 解码JSON响应
	var data map[string]interface{}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&data); err != nil {
		fmt.Println("解码JSON失败:", err)
	}

	//ZKP Verify process
	var decoded []byte
	gk := s.conf.Group.NewElement()
	decoded, _ = base64.StdEncoding.DecodeString(data["gk"].(string))
	gk.Decode(decoded)

	x := s.conf.Group.NewElement()
	decoded, _ = base64.StdEncoding.DecodeString(data["x"].(string))
	x.Decode(decoded)

	y := s.conf.Group.NewElement()
	decoded, _ = base64.StdEncoding.DecodeString(data["y"].(string))
	y.Decode(decoded)

	h := s.conf.Group.NewScalar()
	decoded, _ = base64.StdEncoding.DecodeString(data["h"].(string))
	h.Decode(decoded)

	u := s.conf.Group.NewScalar()
	decoded, _ = base64.StdEncoding.DecodeString(data["u"].(string))
	u.Decode(decoded)

	v := s.conf.Group.NewScalar()
	decoded, _ = base64.StdEncoding.DecodeString(data["v"].(string))
	v.Decode(decoded)

	a1 := s.conf.Group.NewElement().Base().Multiply(u).Add(gk.Multiply(h))
	a2 := x.Copy().Multiply(u).Add(y.Multiply(h))

	hashInput := append(append(append(append(append(s.conf.Group.NewElement().Base().Encode(), gk.Encode()...), x.Encode()...), v.Encode()...), a1.Encode()...), a2.Encode()...)
	h_verify := s.conf.Group.HashToScalar(hashInput, []byte("ZKP: hash to group"))
	if h_verify.Equal(h) != 1 {
		fmt.Printf("ZKP error!")
	}

	// 将结果发送到通道
	resultChan <- y
}

// TODO: topaqueResponse(Variant of oprfResponse to support toprf)
func (s *Server) topaqueResponse(element *group.Element, credentialIdentifier []byte, threshold int) *group.Element {
	str_element := base64.StdEncoding.EncodeToString(element.Encode())
	credID := base64.StdEncoding.EncodeToString(credentialIdentifier)

	var wg sync.WaitGroup
	resultChan := make(chan *group.Element, threshold)

	// 并发发送threshold个请求
	for i := 1; i <= threshold; i++ {
		wg.Add(1)
		url := fmt.Sprintf("1.92.90.89:%d?credID=%s&element=%s", 9090+i, credID, str_element)
		go s.httpResponse(url, &wg, resultChan)
	}

	// 等待所有goroutine完成
	wg.Wait()

	// 关闭通道，确保所有goroutine都已完成
	close(resultChan)

	blindedMessage := s.conf.Group.NewElement().Identity()

	// 从通道读取结果并将y的值相加
	for y := range resultChan {
		blindedMessage.Add(y)
	}

	//return blinded element Aggregated from threshold servers
	return blindedMessage
}

// TODO: oprfResponse
func (s *Server) oprfResponse(element *group.Element, oprfSeed, credentialIdentifier []byte) *group.Element {
	//oprfSeed, credentialIdentifier --> seed
	seed := s.conf.KDF.Expand(
		oprfSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)
	//seed(oprfSeed + credID --> expand), info(const str) --> ku
	//两次调用，生成ku都是相同的
	ku := s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))
	//Evaluate call the func multiply
	return s.conf.OPRF.Evaluate(ku, element)
}

// TODO: Modify RegistrationResponse func to support hpake
// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given
// identifiers.
func (s *Server) HpakeRegistrationResponse(
	req *message.RegistrationRequest,
	serverPublicKey *group.Element,
	credentialIdentifier, oprfSeed []byte,
	client *http.Client,
) *message.RegistrationResponse {
	//oprfseed, credentialIdentifier --> x. in fact, x = 1/(ku + h(uid))
	seed := s.conf.KDF.Expand(
		oprfSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)
	x := s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))

	//New: m = h(pw) ^ blindU ^ blindS, a1 = m, a2 = a1 ^ x
	a1 := s.OPRF.Blind(req.BlindedMessage)
	a2 := a1.Copy().Multiply(x)

	//New: Cryptor Service
	b := s.OPRF.ServiceReg(a1, a2, client)
	z := s.OPRF.UnBlind(b)

	return &message.RegistrationResponse{
		EvaluatedMessage: z,
		Pks:              serverPublicKey,
	}
}

// TODO: Modify RegistrationResponse func to support topaque
// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given
// identifiers.
func (s *Server) TopaqueRegistrationResponse(
	req *message.RegistrationRequest,
	serverPublicKey *group.Element,
	credentialIdentifier []byte,
	threshold int,
) *message.RegistrationResponse {
	z := s.topaqueResponse(req.BlindedMessage, credentialIdentifier, threshold)

	return &message.RegistrationResponse{
		EvaluatedMessage: z,
		Pks:              serverPublicKey,
	}
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given
// identifiers.
func (s *Server) RegistrationResponse(
	req *message.RegistrationRequest,
	serverPublicKey *group.Element,
	credentialIdentifier, oprfSeed []byte,
) *message.RegistrationResponse {
	z := s.oprfResponse(req.BlindedMessage, oprfSeed, credentialIdentifier)

	return &message.RegistrationResponse{
		EvaluatedMessage: z,
		Pks:              serverPublicKey,
	}
}

func (s *Server) hpakeCredentialResponse(
	req *message.CredentialRequest,
	serverPublicKey []byte,
	record *message.RegistrationRecord,
	credentialIdentifier, oprfSeed, maskingNonce []byte,
	client *http.Client,
) *message.CredentialResponse {

	seed := s.conf.KDF.Expand(
		oprfSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)
	x := s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))

	//New: m = h(pw) ^ blindU ^ blindS, a1 = m, a2 = a1 ^ x
	a1 := s.OPRF.Blind(req.BlindedMessage)
	a2 := a1.Copy().Multiply(x)
	tau1 := s.t1.Copy().Multiply(x)
	o := s.conf.OPRF.DeriveKey(seed, []byte(tag.GenSeed))
	tau2 := (s.gs.Copy().Multiply(o).Add(s.t2)).Multiply(x)

	//New: Cryptor Service Map
	b := s.OPRF.ServiceLogin(a1, a2, tau1, tau2, client)
	z := s.OPRF.UnBlind(b)

	//z := s.oprfResponse(req.BlindedMessage, oprfSeed, credentialIdentifier)

	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce, // record.TestMaskNonce = nil
		record.MaskingKey,
		serverPublicKey,
		record.Envelope,
	)

	return message.NewCredentialResponse(z, maskingNonce, maskedResponse)
}

func (s *Server) topaqueCredentialResponse(
	req *message.CredentialRequest,
	serverPublicKey []byte,
	record *message.RegistrationRecord,
	credentialIdentifier, maskingNonce []byte,
	threshold int,
) *message.CredentialResponse {
	z := s.topaqueResponse(req.BlindedMessage, credentialIdentifier, threshold)

	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce,
		record.MaskingKey,
		serverPublicKey,
		record.Envelope,
	)

	return message.NewCredentialResponse(z, maskingNonce, maskedResponse)
}

func (s *Server) credentialResponse(
	req *message.CredentialRequest,
	serverPublicKey []byte,
	record *message.RegistrationRecord,
	credentialIdentifier, oprfSeed, maskingNonce []byte,
) *message.CredentialResponse {
	z := s.oprfResponse(req.BlindedMessage, oprfSeed, credentialIdentifier)

	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce,
		record.MaskingKey,
		serverPublicKey,
		record.Envelope,
	)

	return message.NewCredentialResponse(z, maskingNonce, maskedResponse)
}

// ServerLoginInitOptions enables setting optional values for the session, which default to secure random values if not
// set.
type ServerLoginInitOptions struct {
	// EphemeralSecretKey: optional
	EphemeralSecretKey *group.Scalar
	// Nonce: optional
	Nonce []byte
	// NonceLength: optional
	NonceLength uint
}

func getServerLoginInitOptions(options []ServerLoginInitOptions) *ake.Options {
	var op ake.Options

	if len(options) != 0 {
		op.EphemeralSecretKey = options[0].EphemeralSecretKey
		op.Nonce = options[0].Nonce
		op.NonceLength = options[0].NonceLength
	}

	return &op
}

// SetKeyMaterial set the server's identity and mandatory key material to be used during LoginInit().
// All these values must be the same as used during client registration and remain the same across protocol execution
// for a given registered client.
//
// - serverIdentity can be nil, in which case it will be set to serverPublicKey.
// - serverSecretKey is the server's secret AKE key.
// - serverPublicKey is the server's public AKE key to the serverSecretKey.
// - oprfSeed is the long-term OPRF input seed.
func (s *Server) HpakeSetKeyMaterial(serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte, t1, t2, gs *group.Element) error {
	sks := s.conf.Group.NewScalar()
	if err := sks.Decode(serverSecretKey); err != nil {
		return fmt.Errorf("invalid server AKE secret key: %w", err)
	}

	if sks.IsZero() {
		return ErrZeroSKS
	}

	if len(oprfSeed) != s.conf.Hash.Size() {
		return ErrInvalidOPRFSeedLength
	}

	if len(serverPublicKey) != s.conf.Group.ElementLength() {
		return ErrInvalidPksLength
	}

	if err := s.conf.Group.NewElement().Decode(serverPublicKey); err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	s.keyMaterial = &keyMaterial{
		serverIdentity:  serverIdentity,
		serverSecretKey: sks,
		serverPublicKey: serverPublicKey,
		oprfSeed:        oprfSeed,
		t1:              t1,
		t2:              t2,
		gs:              gs,
	}

	return nil
}

func (s *Server) SetKeyMaterial(serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte) error {
	sks := s.conf.Group.NewScalar()
	if err := sks.Decode(serverSecretKey); err != nil {
		return fmt.Errorf("invalid server AKE secret key: %w", err)
	}

	if sks.IsZero() {
		return ErrZeroSKS
	}

	if len(oprfSeed) != s.conf.Hash.Size() {
		return ErrInvalidOPRFSeedLength
	}

	if len(serverPublicKey) != s.conf.Group.ElementLength() {
		return ErrInvalidPksLength
	}

	if err := s.conf.Group.NewElement().Decode(serverPublicKey); err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	s.keyMaterial = &keyMaterial{
		serverIdentity:  serverIdentity,
		serverSecretKey: sks,
		serverPublicKey: serverPublicKey,
		oprfSeed:        oprfSeed,
	}

	return nil
}

// TODO: Modify LoginInit(ke1, record) to support hpake
// LoginInit responds to a KE1 message with a KE2 message a client record.
func (s *Server) HpakeLoginInit(
	ke1 *message.KE1,
	record *ClientRecord,
	client *http.Client,
	options ...ServerLoginInitOptions,
) (*message.KE2, error) {
	if s.keyMaterial == nil {
		return nil, ErrNoServerKeyMaterial
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return nil, ErrInvalidEnvelopeLength
	}

	// We've checked that the server's public key and the client's envelope are of correct length,
	// thus ensuring that the subsequent xor-ing input is the same length as the encryption pad.

	op := getServerLoginInitOptions(options) // op = nil

	//TODO: credentialResponse func return credential response message
	//New: modify the Calculation method of z
	response := s.hpakeCredentialResponse(ke1.CredentialRequest, s.keyMaterial.serverPublicKey,
		record.RegistrationRecord, record.CredentialIdentifier, s.keyMaterial.oprfSeed, record.TestMaskNonce, client)

	identities := ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.keyMaterial.serverIdentity,
	}
	//SetIdentities sets the client and server identities to their respective public key if not set.
	identities.SetIdentities(record.PublicKey, s.keyMaterial.serverPublicKey)
	//TODO: Response func produce message ke2
	ke2 := s.Ake.Response(s.conf, &identities, s.keyMaterial.serverSecretKey, record.PublicKey, ke1, response, *op)

	return ke2, nil
}

// TODO: Modify LoginInit(ke1, record) to support topaque
// LoginInit responds to a KE1 message with a KE2 message a client record.
func (s *Server) TopaqueLoginInit(
	ke1 *message.KE1,
	record *ClientRecord,
	threshold int,
	options ...ServerLoginInitOptions,
) (*message.KE2, error) {
	if s.keyMaterial == nil {
		return nil, ErrNoServerKeyMaterial
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return nil, ErrInvalidEnvelopeLength
	}

	// We've checked that the server's public key and the client's envelope are of correct length,
	// thus ensuring that the subsequent xor-ing input is the same length as the encryption pad.

	op := getServerLoginInitOptions(options)

	response := s.topaqueCredentialResponse(ke1.CredentialRequest, s.keyMaterial.serverPublicKey,
		record.RegistrationRecord, record.CredentialIdentifier, record.TestMaskNonce, threshold)

	identities := ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.keyMaterial.serverIdentity,
	}
	identities.SetIdentities(record.PublicKey, s.keyMaterial.serverPublicKey)

	ke2 := s.Ake.Response(s.conf, &identities, s.keyMaterial.serverSecretKey, record.PublicKey, ke1, response, *op)

	return ke2, nil
}

// LoginInit responds to a KE1 message with a KE2 message a client record.
func (s *Server) LoginInit(
	ke1 *message.KE1,
	record *ClientRecord,
	options ...ServerLoginInitOptions,
) (*message.KE2, error) {
	if s.keyMaterial == nil {
		return nil, ErrNoServerKeyMaterial
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return nil, ErrInvalidEnvelopeLength
	}

	// We've checked that the server's public key and the client's envelope are of correct length,
	// thus ensuring that the subsequent xor-ing input is the same length as the encryption pad.

	op := getServerLoginInitOptions(options)

	response := s.credentialResponse(ke1.CredentialRequest, s.keyMaterial.serverPublicKey,
		record.RegistrationRecord, record.CredentialIdentifier, s.keyMaterial.oprfSeed, record.TestMaskNonce)

	identities := ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.keyMaterial.serverIdentity,
	}
	identities.SetIdentities(record.PublicKey, s.keyMaterial.serverPublicKey)

	ke2 := s.Ake.Response(s.conf, &identities, s.keyMaterial.serverSecretKey, record.PublicKey, ke1, response, *op)

	return ke2, nil
}

// LoginFinish returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) LoginFinish(ke3 *message.KE3) error {
	if !s.Ake.Finalize(s.conf, ke3) {
		return ErrAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous call to LoginInit() was successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}

// ExpectedMAC returns the expected client MAC if the previous call to LoginInit() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.Ake.ExpectedMAC()
}

// SetAKEState sets the internal state of the AKE server from the given bytes.
func (s *Server) SetAKEState(state []byte) error {
	if len(state) != s.conf.MAC.Size()+s.conf.KDF.Size() {
		return ErrInvalidState
	}

	if err := s.Ake.SetState(state[:s.conf.MAC.Size()], state[s.conf.MAC.Size():]); err != nil {
		return fmt.Errorf("setting AKE state: %w", err)
	}

	return nil
}

// SerializeState returns the internal state of the AKE server serialized to bytes.
func (s *Server) SerializeState() []byte {
	return s.Ake.SerializeState()
}
