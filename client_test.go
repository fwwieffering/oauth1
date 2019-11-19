package oauth1

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func unsignedReq() *http.Request {
	b := ioutil.NopCloser(strings.NewReader("c2&a3=2+q"))
	testReq, _ := http.NewRequest("POST", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", b)
	return testReq
}

var consumerKey = "consumerKey"
var consumerSecret = "consumerSecret"
var tempKey = "temporaryKey"
var tempSecret = "temporarySecret"
var token = "token"
var tokenSecret = "tokenSecret"
var verifier = "verifier"

func decodeSignature(sigmethod SignatureMethod, signature string, signatureBaseString string, clientSecret string, tokenSecret string) error {
	switch sigmethod {
	case Plaintext:
		splitSig := strings.Split(signature, "&")
		if len(splitSig) != 2 {
			return fmt.Errorf("incorrectly formatted signature. Should always have an '&'")
		}
		signatureClientSecret := unescape(splitSig[0])
		signatureOwnerSecret := unescape(splitSig[1])
		if signatureClientSecret != clientSecret || signatureOwnerSecret != tokenSecret {
			return fmt.Errorf("Expected client secret: %s. Received Client secret: %s. Expected owner secret: %s. Received owner secret: %s", clientSecret, signatureClientSecret, tokenSecret, signatureOwnerSecret)
		}
	case HmacSha1:
		correctsig, err := generateSignatureHmacSHA1(signatureBaseString, consumerSecret, tokenSecret)
		if err != nil {
			return fmt.Errorf("couldn't validate signature: %s", err.Error())
		}
		if signature != correctsig {
			return fmt.Errorf("hmac sig did not match expected value.\nExpectedSig:\n%s\nGotSig:\n%s", correctsig, signature)
		}
	case RsaSha1:
		correctSig, err := generateSignatureRsaSHA1(signatureBaseString, rsaKey)
		if err != nil {
			return fmt.Errorf("couldn't validate signature: %s", err.Error())
		}
		if signature != correctSig {
			return fmt.Errorf("rsa sig did not match expected value. Expected: %s. Got: %s", correctSig, signature)
		}
	}

	return nil
}

func validateSignatureMethod(sigmethod string) (SignatureMethod, error) {
	switch sigmethod {
	case "PLAINTEXT":
		return Plaintext, nil
	case "HMAC-SHA1":
		return HmacSha1, nil
	case "RSA-SHA1":
		return RsaSha1, nil
	default:
		return 0, fmt.Errorf("unknown signature method %s", sigmethod)
	}
}

func temporaryCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("authorization")
	if len(authHeader) == 0 {
		http.Error(w, "Expected authorization header", http.StatusBadRequest)
		return
	}
	oauthParams := parseOauthHeader(authHeader)
	if len(oauthParams["oauth_callback"]) == 0 {
		http.Error(w, "missing oauth_callback param", http.StatusBadRequest)
		return
	}
	if len(oauthParams["oauth_consumer_key"]) == 0 || oauthParams["oauth_consumer_key"][0] != consumerKey {
		http.Error(w, fmt.Sprintf("consumer key did not match expected value. Got: %s. Expected: %s", oauthParams["oauth_consumer_key"], consumerKey), http.StatusBadRequest)
		return
	}
	if len(oauthParams["oauth_signature_method"]) == 0 {
		http.Error(w, "missing oauth_signature_method parameter", http.StatusBadRequest)
		return
	}
	sigmethod, err := validateSignatureMethod(oauthParams["oauth_signature_method"][0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(oauthParams["oauth_signature"]) == 0 {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	baseString := signatureBaseStringFromRequest(r)
	err = decodeSignature(sigmethod, oauthParams["oauth_signature"][0], baseString, consumerKey, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bodyContent := url.Values(map[string][]string{
		"oauth_token":              []string{tempKey},
		"oauth_token_secret":       []string{tempSecret},
		"oauth_callback_confirmed": []string{"true"},
	})

	w.Write([]byte(bodyContent.Encode()))
}

func tokenRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("authorization")
	if len(authHeader) == 0 {
		http.Error(w, "Expected authorization header", http.StatusBadRequest)
		return
	}
	oauthParams := parseOauthHeader(authHeader)
	if len(oauthParams["oauth_consumer_key"]) == 0 || oauthParams["oauth_consumer_key"][0] != consumerKey {
		http.Error(w, fmt.Sprintf("consumer key did not match expected value. Got: %s. Expected: %s", oauthParams["oauth_consumer_key"], consumerKey), http.StatusBadRequest)
		return
	}
	if len(oauthParams["oauth_signature_method"]) == 0 {
		http.Error(w, "missing oauth_signature_method parameter", http.StatusBadRequest)
		return
	}
	if len(oauthParams["oauth_verifier"]) == 0 {
		http.Error(w, "missing oauth_verifier parameter", http.StatusBadRequest)
		return
	}
	sigmethod, err := validateSignatureMethod(oauthParams["oauth_signature_method"][0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	baseString := signatureBaseStringFromRequest(r)
	err = decodeSignature(sigmethod, oauthParams["oauth_signature"][0], baseString, consumerSecret, tempSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bodyContent := url.Values(map[string][]string{
		"oauth_token":        []string{token},
		"oauth_token_secret": []string{tokenSecret},
	})
	w.Write([]byte(bodyContent.Encode()))
}

func getServer() *http.Server {
	server := http.NewServeMux()
	server.HandleFunc("/accesstoken", temporaryCredentialsHandler)
	server.HandleFunc("/requesttoken", tokenRequestHandler)
	return &http.Server{
		Handler: server,
		Addr:    "127.0.0.1:2222",
	}
}

func TestMain(m *testing.M) {
	server := getServer()
	go server.ListenAndServeTLS("server.crt", "server.key")
	defer server.Close()
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestNewClient(t *testing.T) {
	opts := ClientOptions{
		ClientKey:           "9djdj82h48djs9d2",
		ResourceOwnerKey:    "kkk9d7dh3k39sjv7",
		ResourceOwnerSecret: resourceOwnerSecret,
		ClientSecret:        clientSecret,
	}
	_, expectedErr := NewClient(opts)
	if expectedErr == nil {
		t.Fatalf("expected error creating client with no signaturemethod but got none")
	}

	opts.SignatureMethod = Plaintext
	opts.HTTPClient = &http.Client{}

	_, unexexpectedErr := NewClient(opts)
	if unexexpectedErr != nil {
		t.Fatalf("unexpected error creating client: %s", unexexpectedErr.Error())
	}
}

func TestSignRequest(t *testing.T) {

	checkParams := func(params []param, opts ClientOptions) {
		errMsgTemplate := "Incorrect %s.\nExpected:\n%s\nGot:\n%s\n"
		for _, p := range params {
			switch p.key {
			case "oauth_consumer_key":
				if p.val != opts.ClientKey {
					t.Fatalf(errMsgTemplate, p.key, opts.ClientKey, p.val)
				}
			case "oauth_token":
				if p.val != opts.ResourceOwnerKey {
					t.Fatalf(errMsgTemplate, p.key, opts.ResourceOwnerKey, p.val)
				}
			case "oauth_signature_method":
				if p.val != opts.SignatureMethod.ToString() {
					t.Fatalf(errMsgTemplate, p.key, opts.SignatureMethod.ToString(), p.val)
				}
			}
		}
	}

	opts := ClientOptions{
		ClientKey:           "9djdj82h48djs9d2",
		ResourceOwnerKey:    "kkk9d7dh3k39sjv7",
		ResourceOwnerSecret: resourceOwnerSecret,
		ClientSecret:        clientSecret,
		SignatureMethod:     Plaintext,
	}
	errC, _ := NewClient(opts)
	errC.signatureMethod = 0
	errReq := unsignedReq()
	expectedErr := errC.SignRequest(errReq)
	if expectedErr == nil {
		t.Fatalf("expected error signing request but got none")
	}
	errC.signatureMethod = RsaSha1
	expectedErr = errC.SignRequest(errReq)
	if expectedErr == nil {
		t.Fatalf("expected error signing request but got none")
	}

	textC, _ := NewClient(opts)
	textReq := unsignedReq()
	err := textC.SignRequest(textReq)
	if err != nil {
		t.Fatalf("unexpected error signing request: %s", err.Error())
	}
	textParams := collectAllParams(textReq)
	checkParams(textParams, opts)

	opts.SignatureMethod = HmacSha1
	hmacC, _ := NewClient(opts)
	hmacReq := unsignedReq()
	err = hmacC.SignRequest(hmacReq)
	if err != nil {
		t.Fatalf("unexpected error signing request: %s", err.Error())
	}
	params := collectAllParams(hmacReq)
	checkParams(params, opts)

	opts.SignatureMethod = RsaSha1
	opts.RSAPrivateKey = rsaKey
	rsaC, _ := NewClient(opts)
	rsaReq := unsignedReq()
	rsaC.SignRequest(rsaReq)
	err = hmacC.SignRequest(hmacReq)
	if err != nil {
		t.Fatalf("unexpected error signing request: %s", err.Error())
	}
	rsaParams := collectAllParams(rsaReq)
	checkParams(rsaParams, opts)
}

func TestRequestTemporaryCredentialsUnitHappy(t *testing.T) {

	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		ClientKey:       consumerKey,
		ClientSecret:    consumerSecret,
		SignatureMethod: HmacSha1,
	})

	if err != nil {
		t.Fatalf("Error creating client: %s", err.Error())
	}

	_, err = client.RequestTemporaryCredentials("https://127.0.0.1:2222/accesstoken", "oob")

	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestRequestTemporaryCredentialsUnitFailures(t *testing.T) {

	client, err := NewClient(ClientOptions{
		ClientKey:       consumerKey,
		ClientSecret:    consumerSecret,
		SignatureMethod: HmacSha1,
	})

	if err != nil {
		t.Fatalf("Error creating client: %s", err.Error())
	}
	// induce tls error
	_, err = client.RequestTemporaryCredentials("https://127.0.0.1:2222/accesstoken", "oob")

	if err == nil {
		t.Fatalf("expected error but got none")
	}

	// induce signature error by not providing cert
	client.signatureMethod = RsaSha1
	client.rsaPrivateKey = []byte("foo")
	_, err = client.RequestTemporaryCredentials("https://127.0.0.1:2222/accesstoken", "oob")
	if err == nil {
		t.Fatalf("expected error but got none")
	}
}

func TestTemporaryCredsIntegration(t *testing.T) {
	// http://term.ie/oauth/example/ is a public demo oauth1 server
	testCases := []struct {
		url    string
		method SignatureMethod
	}{
		{
			method: HmacSha1,
			url:    "http://term.ie/oauth/example/request_token.php",
		},
		// fairly certain the plaintext implementation is bugged and is expecting the oauth_signature
		// to be escaped twice
		// {
		// 	method: Plaintext,
		// 	url:    "http://term.ie/oauth/example/request_token.php",
		// },
	}
	for _, c := range testCases {
		client, err := NewClient(ClientOptions{
			ClientKey:       "key",
			ClientSecret:    "secret",
			SignatureMethod: c.method,
		})

		tempCreds, err := client.RequestTemporaryCredentials(c.url, "oob")
		if err != nil {
			t.Fatalf(err.Error())
		}
		if tempCreds.Token != "requestkey" || tempCreds.TokenSecret != "requestsecret" {
			t.Fatalf("unexpected request token vals for signature method %s: %+v", c.method.ToString(), tempCreds)
		}
	}
}

func TestRequestTokenUnitHappy(t *testing.T) {
	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		ClientKey:       consumerKey,
		ClientSecret:    consumerSecret,
		SignatureMethod: HmacSha1,
	})

	_, err = client.RequestToken("https://127.0.0.1:2222/requesttoken", &TemporaryCredentials{Token: tempKey, TokenSecret: tempSecret}, verifier)

	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestRequestTokenUnitFailures(t *testing.T) {

	client, err := NewClient(ClientOptions{
		ClientKey:       consumerKey,
		ClientSecret:    consumerSecret,
		SignatureMethod: HmacSha1,
	})

	if err != nil {
		t.Fatalf("Error creating client: %s", err.Error())
	}
	// induce tls error
	_, err = client.RequestToken("https://127.0.0.1:2222/requesttoken", &TemporaryCredentials{Token: tempKey, TokenSecret: tempSecret}, verifier)

	if err == nil {
		t.Fatalf("expected error but got none")
	}
	// induce signature error by not providing cert
	client.signatureMethod = RsaSha1
	client.rsaPrivateKey = []byte("foo")
	_, err = client.RequestToken("https://127.0.0.1:2222/requesttoken", &TemporaryCredentials{Token: tempKey, TokenSecret: tempSecret}, verifier)
	if err == nil {
		t.Fatalf("expected error but got none")
	}
}

func TestAuthorizationURL(t *testing.T) {
	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		ClientKey:       consumerKey,
		ClientSecret:    consumerSecret,
		SignatureMethod: HmacSha1,
	})

	if err != nil {
		t.Fatalf("Error creating client: %s", err.Error())
	}

	tempCreds, err := client.RequestTemporaryCredentials("https://127.0.0.1:2222/accesstoken", "oob")

	authURL, _ := client.AuthorizationURL("https://localhost/authuri", tempCreds)
	if authURL != fmt.Sprintf("https://localhost/authuri?oauth_token=%s", tempCreds.Token) {
		t.Fatalf("did not get expected auth url")
	}
}
