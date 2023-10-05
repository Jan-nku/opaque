// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/Jan-nku/opaque/internal/encoding"
	group "github.com/bytemare/crypto"
	"math/big"
	"net/http"
)

// New: add oprf Server
type Server struct {
	blind *group.Scalar
	Identifier
}

// Evaluate evaluates the blinded input with the given key.
func (i Identifier) Evaluate(privateKey *group.Scalar, blindedElement *group.Element) *group.Element {
	return blindedElement.Copy().Multiply(privateKey)
}

// New: add server blind func
func (s *Server) Blind(blindedElement *group.Element) *group.Element {
	if s.blind == nil {
		s.blind = s.Group().NewScalar().Random()
	}
	return blindedElement.Copy().Multiply(s.blind)
}

// New: add server unblind func
func (s *Server) UnBlind(blindedElement *group.Element) *group.Element {
	invert := s.blind.Copy().Invert()
	u := blindedElement.Copy().Multiply(invert)
	return u
}

func (s *Server) ServiceReg(a1 *group.Element, a2 *group.Element, client *http.Client) *group.Element {
	str_a1 := encoding.ByteArrayToBase64String(a1.Encode())
	str_a2 := encoding.ByteArrayToBase64String(a2.Encode())

	url := "https://123.249.125.222/reg?a1=" + str_a1 + "&a2=" + str_a2

	// 发送HTTPS GET请求
	response, err := client.Get(url)
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

	blindedMessage := s.Group().NewElement()
	if err := blindedMessage.Decode(encoding.Base64StringToByteArray(data["beta"].(string))); err != nil {
		return nil
	}

	//ZKP Verify process, h = g ^ kc1
	h := s.Group().NewElement()
	if err := h.Decode(encoding.Base64StringToByteArray(data["h"].(string))); err != nil {
		return nil
	}
	x1 := s.Group().NewElement()
	if err := x1.Decode(encoding.Base64StringToByteArray(data["x1"].(string))); err != nil {
		return nil
	}
	x2 := s.Group().NewElement()
	if err := x2.Decode(encoding.Base64StringToByteArray(data["x2"].(string))); err != nil {
		return nil
	}
	k1 := s.Group().NewScalar()
	if err := k1.Decode(encoding.Base64StringToByteArray(data["k1"].(string))); err != nil {
		return nil
	}
	k2 := s.Group().NewScalar()
	if err := k2.Decode(encoding.Base64StringToByteArray(data["k2"].(string))); err != nil {
		return nil
	}

	//compute hash result c
	str := "1:AwpljT4HsBVSyWx1Pem9S9cgMuJ9FSuAboqjPOWhGvS3" + data["h"].(string) + str_a1 + str_a2 + data["beta"].(string) + data["x1"].(string) + data["x2"].(string)
	sha256Hash := sha256.Sum256([]byte(str))
	hashInt := new(big.Int)
	hashInt.SetBytes(sha256Hash[:])
	c := s.Group().NewScalar()
	if err := c.SetInt(hashInt); err != nil {
		return nil
	}

	left := a1.Copy().Multiply(k1).Add(a2.Copy().Multiply(k2))
	right := x1.Add(x2).Add(blindedMessage.Copy().Multiply(c))
	/*	if left.Equal(right) == 1 {
			fmt.Println("Zero knowledge proof is correct.")
		} else {
			fmt.Println("Zero knowledge proof is not correct.")
		}*/
	if left.Equal(right) != 1 {
		return nil
	}

	return blindedMessage
}

func (s *Server) ServiceLogin(a1, a2, tau1, tau2 *group.Element, client *http.Client) *group.Element {
	str_a1 := encoding.ByteArrayToBase64String(a1.Encode())
	str_a2 := encoding.ByteArrayToBase64String(a2.Encode())
	str_tau1 := encoding.ByteArrayToBase64String(tau1.Encode())
	str_tau2 := encoding.ByteArrayToBase64String(tau2.Encode())

	url := "https://123.249.125.222/login?a1=" + str_a1 + "&a2=" + str_a2 + "&t1=" + str_tau1 + "&t2=" + str_tau2

	// 发送HTTPS GET请求
	response, err := client.Get(url)
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

	blindedMessage := s.Group().NewElement()
	if err := blindedMessage.Decode(encoding.Base64StringToByteArray(data["beta"].(string))); err != nil {
		return nil
	}

	//ZKP Verify process, h = g ^ kc1
	h := s.Group().NewElement()
	if err := h.Decode(encoding.Base64StringToByteArray(data["h"].(string))); err != nil {
		return nil
	}
	x1 := s.Group().NewElement()
	if err := x1.Decode(encoding.Base64StringToByteArray(data["x1"].(string))); err != nil {
		return nil
	}
	x2 := s.Group().NewElement()
	if err := x2.Decode(encoding.Base64StringToByteArray(data["x2"].(string))); err != nil {
		return nil
	}
	k1 := s.Group().NewScalar()
	if err := k1.Decode(encoding.Base64StringToByteArray(data["k1"].(string))); err != nil {
		return nil
	}
	k2 := s.Group().NewScalar()
	if err := k2.Decode(encoding.Base64StringToByteArray(data["k2"].(string))); err != nil {
		return nil
	}

	//compute hash result c
	str := "1:AwpljT4HsBVSyWx1Pem9S9cgMuJ9FSuAboqjPOWhGvS3" + data["h"].(string) + str_a1 + str_a2 + data["beta"].(string) + data["x1"].(string) + data["x2"].(string)
	sha256Hash := sha256.Sum256([]byte(str))
	hashInt := new(big.Int)
	hashInt.SetBytes(sha256Hash[:])
	c := s.Group().NewScalar()
	if err := c.SetInt(hashInt); err != nil {
		return nil
	}

	left := a1.Copy().Multiply(k1).Add(a2.Copy().Multiply(k2))
	right := x1.Add(x2).Add(blindedMessage.Copy().Multiply(c))
	/*	if left.Equal(right) == 1 {
			fmt.Println("Zero knowledge proof is correct.")
		} else {
			fmt.Println("Zero knowledge proof is not correct.")
		}*/
	if left.Equal(right) != 1 {
		return nil
	}

	return blindedMessage
}
