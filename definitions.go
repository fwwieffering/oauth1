// Package oauth1 provides a client for oauth1 authorization following RFC-5849.
// See https://tools.ietf.org/html/rfc5849 for details on the specification.
// Oauth Bible http://oauthbible.com/ has details on different oauth 1.0 flows
package oauth1

import (
	"fmt"
	"reflect"
)

// SignatureMethod constant for passing the Oauth1 Signature Method
// RFC 5849 3.4
type SignatureMethod uint

const (
	// Plaintext RFC 5849 3.4.4
	Plaintext SignatureMethod = iota + 1
	// HmacSha1 RFC 5849 3.4.3
	HmacSha1
	// RsaSha1 RFC 5849 3.4.2
	RsaSha1
)

// TemporaryCredentials contains the credentials returned from the access token endpoint
type TemporaryCredentials struct {
	// oauth_token: The temporary credentials identifier.
	Token string
	// oauth_token_secret The temporary credentials shared-secret.
	TokenSecret string
}

// Credentials contains the credentials returned from the token request endpoint
type Credentials struct {
	// oauth_token: aka Resource Owner Key
	Token string
	// oauth_token_secret: aka Resource Owner Secret
	TokenSecret string
}

// ToString conversts a signature method to a string value
func (s SignatureMethod) ToString() string {
	var str string
	switch s {
	case Plaintext:
		str = "PLAINTEXT"
	case HmacSha1:
		str = "HMAC-SHA1"
	case RsaSha1:
		str = "RSA-SHA1"
	}
	return str
}

type param struct {
	key string
	val string
}

func (p *param) encode() {
	p.key = escape(p.key)
	p.val = escape(p.val)
}

func (p *param) display() string {
	return fmt.Sprintf("%s=%s", p.key, p.val)
}

type oauthParams struct {
	ConsumerKey     string `key:"oauth_consumer_key"`
	Token           string `key:"oauth_token"`
	SignatureMethod string `key:"oauth_signature_method"`
	Timestamp       string `key:"oauth_timestamp"`
	Nonce           string `key:"oauth_nonce"`
	Version         string `key:"oauth_version"` // always 1.0
	// fields used when obtaining credentials
	Verifier string `key:"oauth_verifier"`
	// oauth_callback:  An absolute URI back to which the server will
	// redirect the resource owner when the Resource Owner
	// Authorization step (Section 2.2) is completed.  If
	// the client is unable to receive callbacks or a
	// callback URI has been established via other means,
	// the parameter value MUST be set to "oob" (case
	// sensitive), to indicate an out-of-band
	// configuration.
	Callback  string `key:"oauth_callback"`
	Signature string `key:"oauth_signature"`
}

func (op oauthParams) toParams() []param {
	res := make([]param, 0)

	val := reflect.ValueOf(op)
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i).String()
		tag := typ.Field(i).Tag.Get("key")
		if len(field) > 0 && len(tag) > 0 {
			res = append(res, param{key: tag, val: field})
		}
	}
	return res
}

func (op oauthParams) toMap() map[string][]string {
	res := make(map[string][]string, 0)

	val := reflect.ValueOf(op)
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i).String()
		tag := typ.Field(i).Tag.Get("key")
		if len(field) > 0 && len(tag) > 0 {
			res[tag] = []string{field}
		}
	}
	return res

}

func (op oauthParams) toHeader() string {
	params := op.toParams()

	header := "OAuth "

	for i := 0; i < len(params); i++ {
		item := fmt.Sprintf("%s=\"%s\"", escape(params[i].key), escape(params[i].val))
		header += item
		if i < (len(params) - 1) {
			header += ","
		}
	}
	return header
}

// oauthParamsFromHeader parses the oauth header into the oauthParams struct
func oauthParamsFromHeader(authHeader string) oauthParams {
	parsedHeader := parseOauthHeader(authHeader)
	res := &oauthParams{}

	val := reflect.ValueOf(res).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		typField := typ.Field(i)
		tag := typField.Tag.Get("key")

		if len(tag) > 0 {
			val := parsedHeader[tag]
			if len(val) > 0 {
				field.SetString(val[0])
			}
		}
	}
	return *res
}

// TODO: These params will vary depending on what type of creds we have
// for example:
// - when requesting temporary credentials, oauth_callback is required
// - when authorizing oauth_token must be the temporary credentials
// - must use oauth_verifier if doing token request
// TODO: make different functions for those use cases ^^
func (c Client) createOauthParams() oauthParams {
	return oauthParams{
		ConsumerKey:     c.clientKey,
		SignatureMethod: c.signatureMethod.ToString(),
		Timestamp:       timestamp(),
		Nonce:           nonce(),
		Version:         "1.0",
		Token:           string(c.resourceOwnerKey),
	}
}

func (c Client) createOauthParamsTemporaryCredentials(callbackURI string) oauthParams {
	return oauthParams{
		Callback:        callbackURI,
		ConsumerKey:     c.clientKey,
		SignatureMethod: c.signatureMethod.ToString(),
		Nonce:           nonce(),
		Timestamp:       timestamp(),
		Version:         "1.0",
	}
}

func (c Client) createOauthParamsTokenRequest(verifier string, creds *TemporaryCredentials) oauthParams {
	return oauthParams{
		Verifier:    verifier,
		ConsumerKey: c.clientKey,
		Token:       creds.Token,
		Nonce:       nonce(),
		Timestamp:   timestamp(),
		Version:     "1.0",
	}
}
