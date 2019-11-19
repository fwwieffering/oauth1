package oauth1

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Client oauth1 client
type Client struct {
	http                *http.Client
	signatureMethod     SignatureMethod
	clientKey           string
	clientSecret        string
	resourceOwnerKey    string
	resourceOwnerSecret string
	rsaPrivateKey       []byte
}

// ClientOptions is the parameter option for creating a
// new Oauth1 Client
type ClientOptions struct {
	// net/http client to use for http requests
	HTTPClient *http.Client

	// SignatureMethod the oauth1 signature method
	SignatureMethod SignatureMethod
	// Also known as consumer key or client token
	ClientKey string
	// Also known as consumer secret or client secret
	ClientSecret string
	// also known as token
	ResourceOwnerKey string
	// also known as token secret
	ResourceOwnerSecret string
	RSAPrivateKey       []byte
}

// NewClient creates a new oauth1 client
func NewClient(opts ClientOptions) (*Client, error) {
	var c *http.Client

	if opts.HTTPClient == nil {
		c = &http.Client{}
	} else {
		c = opts.HTTPClient
	}

	// uninitialized SignatureMethod should be 0
	if opts.SignatureMethod == 0 || opts.SignatureMethod.ToString() == "" {
		return nil, fmt.Errorf("oauth1: Must provide SignatureMethod parameter")
	}

	return &Client{
		signatureMethod:     opts.SignatureMethod,
		http:                c,
		clientKey:           opts.ClientKey,
		clientSecret:        opts.ClientSecret,
		resourceOwnerKey:    opts.ResourceOwnerKey,
		resourceOwnerSecret: opts.ResourceOwnerSecret,
		rsaPrivateKey:       opts.RSAPrivateKey,
	}, nil
}

// Do performs http request req with oauth1 authorization
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	err := c.SignRequest(req)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// SignRequest signs an oauth1 request, setting the oauth headers and
// oauth_signature based on the clients' SignatureMethod.
// The passed http.Request is modified in place
func (c *Client) SignRequest(req *http.Request) error {
	// generate non oauth_signature params
	params := c.createOauthParams()

	signatureErr := c.signRequest(params, req)

	if signatureErr != nil {
		return signatureErr
	}
	return nil
}

func (c *Client) generateSignature(params []param, baseURI string, httpMethod string) (string, error) {
	return generateSignature(params, baseURI, httpMethod, c.signatureMethod, &Credentials{TokenSecret: c.clientSecret}, &Credentials{TokenSecret: c.resourceOwnerSecret}, c.rsaPrivateKey)
}

// signRequest generates the default signature for authenticated requests
// not used for requesting access tokens, request tokens
func (c *Client) signRequest(oauth oauthParams, req *http.Request) error {
	method := req.Method
	baseURI := getBaseStrURI(req.URL.Scheme, req.Host, req.URL.Port(), req.URL.EscapedPath())
	params := collectParams(req, oauth)

	signature, err := c.generateSignature(params, baseURI, method)
	if err != nil {
		return err
	}

	oauth.Signature = signature

	req.Header.Add("Authorization", oauth.toHeader())
	return nil
}

// RequestTemporaryCredentials returns temporary credentials from the oauth1 server.
// See https://tools.ietf.org/html/rfc5849#section-2.1 for more information on the Temporary Credentials process
func (c *Client) RequestTemporaryCredentials(temporaryCredentialsURI string, callbackURI string) (*TemporaryCredentials, error) {
	// When making the request, the client authenticates using only the
	// client credentials.  The client MAY omit the empty "oauth_token"
	// protocol parameter from the request and MUST use the empty string as
	// the token secret value.
	params := c.createOauthParamsTemporaryCredentials(callbackURI)

	// zero this out in case it was somehow set b/c it could be used in signing
	c.resourceOwnerSecret = ""
	req, _ := http.NewRequest("POST", temporaryCredentialsURI, nil)

	// Since the request results in the transmission of plain text
	// credentials in the HTTP response, the server MUST require the use of
	// a transport-layer mechanisms such as TLS or Secure Socket Layer (SSL)
	// (or a secure channel with equivalent protections).

	// ignore this because integration test server does not provide it
	// if req.URL.Scheme != "https" {
	// 	return nil, fmt.Errorf("oauth1: the temporary credentials uri must https")
	// }
	err := c.signRequest(params, req)

	if err != nil {
		return nil, err
	}

	response, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth1: error making temporary credentials request %s", err.Error())
	}
	responseBody, _ := ioutil.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("oauth1: error requesting temporary credentials from server: %s", string(responseBody))
	}

	// The server MUST verify (Section 3.2) the request and if valid,
	// respond back to the client with a set of temporary credentials (in
	// the form of an identifier and shared-secret).  The temporary
	// credentials are included in the HTTP response body using the
	// "application/x-www-form-urlencoded" content type as defined by
	// [W3C.REC-html40-19980424] with a 200 status code (OK).

	// The response contains the following REQUIRED parameters:

	// oauth_token
	// 	  The temporary credentials identifier.

	// oauth_token_secret
	// 	  The temporary credentials shared-secret.

	// oauth_callback_confirmed
	// 	  MUST be present and set to "true".  The parameter is used to
	// 	  differentiate from previous versions of the protocol.

	// Note that even though the parameter names include the term 'token',
	// these credentials are not token credentials, but are used in the next
	// two steps in a similar manner to token credentials.
	oauthValues, err := url.ParseQuery(string(responseBody))
	if err != nil {
		return nil, fmt.Errorf("oauth1: unable to parse temporary credentials response %s", err.Error())
	}

	creds := &TemporaryCredentials{
		Token:       oauthValues.Get("oauth_token"),
		TokenSecret: oauthValues.Get("oauth_token_secret"),
	}
	if len(creds.Token) == 0 && len(creds.TokenSecret) == 0 {
		return nil, fmt.Errorf("oauth1: expected oauth_token and oauth_token_secret in response. Got: %s", string(responseBody))
	}
	// technically this must be true, but better to be forgiving
	// callbackConfirmed := oauthValues.Get("oauth_callback_confirmed")

	// if callbackConfirmed != "true" {
	// 	return nil, fmt.Errorf("oauth1: oauth_callback_confirmed returned from server must be `true`. Was: %s", callbackConfirmed)
	// }
	return creds, nil
}

// AuthorizationURL returns the URL for resource owner authorization with the provided TemporaryCredentials.
// See http://tools.ietf.org/html/rfc5849#section-2.2 for information about resource owner authorization.
func (c *Client) AuthorizationURL(authorizationURI string, creds *TemporaryCredentials) (string, error) {
	parsedURI, err := url.Parse(authorizationURI)
	if err != nil {
		return "", fmt.Errorf("oauth1: unable to parse authorizationURI %s", err.Error())
	}

	baseURI := getBaseStrURI(parsedURI.Scheme, parsedURI.Hostname(), parsedURI.Port(), parsedURI.EscapedPath())
	// add oauth_token to whatever query params are already in the authorizationuri
	queryParans := parsedURI.Query()
	queryParans.Add("oauth_token", creds.Token)

	return baseURI + "?" + queryParans.Encode(), nil
}

// RequestToken when passed a uri, temporary credentials, and an `oauth_verifier` value returns an authenticated token and token_secret
// see https://tools.ietf.org/html/rfc5849#section-2.3 for more detail on the oauth1 flow
func (c *Client) RequestToken(tokenURI string, tempCreds *TemporaryCredentials, verifier string) (*Credentials, error) {
	oauthParams := c.createOauthParamsTokenRequest(verifier, tempCreds)

	req, _ := http.NewRequest("POST", tokenURI, nil)
	params := collectParams(req, oauthParams)

	signature, err := generateSignature(
		params,
		getBaseStrURI(req.URL.Scheme, req.Host, req.URL.Port(), req.URL.EscapedPath()),
		req.Method,
		c.signatureMethod,
		&Credentials{Token: c.clientKey, TokenSecret: c.clientSecret},
		&Credentials{Token: tempCreds.Token, TokenSecret: tempCreds.TokenSecret},
		c.rsaPrivateKey,
	)

	if err != nil {
		return nil, err
	}
	oauthParams.Signature = signature
	req.Header.Add("Authorization", oauthParams.toHeader())

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth1: error making token request %s", err.Error())
	}

	bodyContent, _ := ioutil.ReadAll(res.Body)

	parsedBody, err := url.ParseQuery(string(bodyContent))
	if err != nil {
		return nil, fmt.Errorf("oauth1: unable to parse token request response %s", err.Error())
	}

	creds := &Credentials{
		Token:       parsedBody.Get("oauth_token"),
		TokenSecret: parsedBody.Get("oauth_token_secret"),
	}
	return creds, nil
}
