package oauth1

import (
	"fmt"
	"net/http"
)

func Example_redirectauth() {
	// example of redirect based oauth1
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
}
