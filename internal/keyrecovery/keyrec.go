// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keyrecovery

import (
	group "github.com/bytemare/crypto"

	"github.com/Jan-nku/opaque/internal"
	"github.com/Jan-nku/opaque/internal/encoding"
	"github.com/Jan-nku/opaque/internal/oprf"
	"github.com/Jan-nku/opaque/internal/tag"
)

// TODO: randomizedPwd, nonce --> seed -->sk --> pk
func deriveAuthKeyPair(conf *internal.Configuration, randomizedPwd, nonce []byte) (*group.Scalar, *group.Element) {
	seed := conf.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), internal.SeedLength)
	sk := oprf.IDFromGroup(conf.Group).DeriveKey(seed, []byte(tag.DerivePrivateKey))

	return sk, conf.Group.Base().Multiply(sk)
}

func getPubkey(conf *internal.Configuration, randomizedPwd, nonce []byte) *group.Element {
	//getPubkey 调用 deriveAuthKeyPair 函数， 私钥丢弃
	_, pk := deriveAuthKeyPair(conf, randomizedPwd, nonce)
	return pk
}

func recoverKeys(
	conf *internal.Configuration,
	randomizedPwd, nonce []byte,
) (clientSecretKey *group.Scalar, clientPublicKey *group.Element) {
	return deriveAuthKeyPair(conf, randomizedPwd, nonce)
}
