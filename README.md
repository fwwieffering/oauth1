# oauth1
[![Godoc](https://godoc.org/github.com/fwwieffering/oauth1?status.svg)](http://godoc.org/github.com/fwwieffering/oauth1)
[![Go Report Card](https://goreportcard.com/badge/github.com/fwwieffering/oauth1)](https://goreportcard.com/report/github.com/fwwieffering/oauth1)


https://tools.ietf.org/html/rfc5849

An oauth1 client implementation for golang. 

## Examples

One legged oauth
```golang
	// in one legged auth, you already have the client and resource owner keys
	c, _ := NewClient(ClientOptions{
		ClientKey:           "consumerkey",
		ClientSecret:        "consumersecret",
		ResourceOwnerKey:    "token",
		ResourceOwnerSecret: "tokensecret",
	})
	// access protected resources
	req, _ := http.NewRequest("GET", "http://localhost:8080/protected/resource", nil)
	c.Do(req)
```

Redirect based auth
```golang
	// In redirect auth you only have client credentials to start
	// see https://tools.ietf.org/html/rfc5849#section-2
	// and http://oauthbible.com/#oauth-10a-three-legged for more info
	// instantiate oauth client with client credentials
	clientToken := "foo"
	clientSecret := "bar"

	initialClient, _ := NewClient(ClientOptions{
		ClientKey:       clientToken,
		ClientSecret:    clientSecret,
		SignatureMethod: Plaintext,
	})
	// retrieve temporary token
	tempCreds, _ := initialClient.RequestTemporaryCredentials("http://localhost:8080/initiate", "oob")

	// get authorization uri
	uri, _ := initialClient.AuthorizationURL("http://localhost:8080/authorize", tempCreds)
	fmt.Println(uri)
	// off screen - redirect to uri and authenticate
	// retrieve `oauth_verifier` response

	// retrieve permanent token/secret
	token, _ := initialClient.RequestToken("http://localhost:8080/token", tempCreds, "verifier string")

	// now authenticated, provide all creds to client
	c, _ := NewClient(ClientOptions{
		ClientKey:           clientToken,
		ClientSecret:        clientSecret,
		ResourceOwnerKey:    token.Token,
		ResourceOwnerSecret: token.TokenSecret,
	})
	// and access protected resources
	req, _ := http.NewRequest("GET", "http://localhost:8080/protected/resource", nil)
	c.Do(req)
```