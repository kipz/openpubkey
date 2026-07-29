// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestCosSimple(t *testing.T) {
	cosP := CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}
	redirectURI := fmt.Sprintf("%s/%s", "http://localhost:5555", cosP.CallbackPath)

	initAuthSig, nonce, err := cosP.CreateInitAuthSig(redirectURI)
	require.NotNil(t, initAuthSig)
	require.NotNil(t, nonce)
	require.NoError(t, err)

	pktJson := []byte("fake pkt bytes")
	sig1 := []byte("fake signature one bytes")
	authUri, err := cosP.initAuthURI(pktJson, sig1)
	require.NotNil(t, authUri)
	require.Equal(t, "https://example.com/mfa-auth-init?pkt=ZmFrZSBwa3QgYnl0ZXM&sig1=fake+signature+one+bytes", authUri)
	require.NoError(t, err)

	sig2 := []byte("fake signature two bytes")
	authCodeUri, err := cosP.authcodeURI(sig2)
	require.NotNil(t, authCodeUri)
	require.Equal(t, "https://example.com/sign?sig2=fake+signature+two+bytes", authCodeUri)
	require.NoError(t, err)
}

// TestRequestTokenCallbackBindsLoopback pins two properties of the callback
// listener that RequestToken opens for the cosigner redirect:
//
//  1. It is bound to loopback, so the callback endpoint is not reachable from
//     other hosts on the network.
//  2. The redirect URI advertised to the cosigner is the exact address that
//     was bound.
//
// Property 2 matters because "localhost" can resolve to both 127.0.0.1 and
// ::1. Binding one name and advertising the other lets the browser connect to
// a different address family than the one we are listening on, in which case
// the cosigner callback is silently never delivered. Asserting that the
// advertised host is a loopback IP literal that actually accepts a connection
// keeps the bind target and the navigation target in agreement.
func TestRequestTokenCallbackBindsLoopback(t *testing.T) {
	alg := jose.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	pkt, err := mocks.GenerateMockPKToken(t, signer, alg)
	require.NoError(t, err, "failed to generate mock PK Token")

	cosP := CosignerProvider{
		Issuer:       "https://example.com",
		CallbackPath: "/mfaredirect",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	redirCh := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// This blocks until the cosigner calls back or ctx is cancelled. We
		// only care about the redirect URI it publishes, so we cancel below.
		_, _ = cosP.RequestToken(ctx, signer, pkt, redirCh)
	}()

	var initAuthURI string
	select {
	case initAuthURI = <-redirCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for RequestToken to publish the init auth URI")
	}

	// The redirect URI is carried inside the signed InitMFAAuth message that
	// is sent to the cosigner as the sig1 query parameter.
	parsed, err := url.Parse(initAuthURI)
	require.NoError(t, err)
	sig1 := parsed.Query().Get("sig1")
	require.NotEmpty(t, sig1, "init auth URI is missing the sig1 parameter")

	segments := strings.Split(sig1, ".")
	require.Len(t, segments, 3, "sig1 should be a compact JWS")
	payload, err := util.Base64DecodeForJWT([]byte(segments[1]))
	require.NoError(t, err)

	var msg msgs.InitMFAAuth
	require.NoError(t, json.Unmarshal(payload, &msg))

	redirectURI, err := url.Parse(msg.RedirectUri)
	require.NoError(t, err)

	host := redirectURI.Hostname()
	ip := net.ParseIP(host)
	require.NotNil(t, ip,
		"redirect URI host must be an IP literal so the advertised address is unambiguous, got %q", host)
	require.True(t, ip.IsLoopback(),
		"redirect URI must point at loopback, got %q", host)

	// The advertised address must be the socket we actually bound. If these
	// diverged (for example binding 127.0.0.1 but advertising a name that
	// resolves to ::1 first) this dial fails.
	conn, err := net.DialTimeout("tcp", redirectURI.Host, 5*time.Second)
	require.NoError(t, err, "advertised redirect URI %q is not the bound listener", redirectURI.Host)
	require.NoError(t, conn.Close())

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RequestToken did not return after context cancellation")
	}
}
