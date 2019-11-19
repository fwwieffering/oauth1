package oauth1

import "net/http"

func Example_onelegged() {
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
}
