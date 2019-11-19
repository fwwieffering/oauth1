package oauth1

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

// returns example request as specified in the rfc
func rfcRequest() *http.Request {
	b := ioutil.NopCloser(strings.NewReader("c2&a3=2+q"))
	req, _ := http.NewRequest("POST", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", b)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", `OAuth realm="Example",
	oauth_consumer_key="9djdj82h48djs9d2",
	oauth_token="kkk9d7dh3k39sjv7",
	oauth_signature_method="HMAC-SHA1",
	oauth_timestamp="137131201",
	oauth_nonce="7d8f3e4a",
	oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"`)
	return req
}

func TestNormalizeParams(t *testing.T) {
	params := []param{
		param{key: "b5", val: "=%3D"},
		param{key: "a3", val: "a"},
		param{key: "c@", val: ""},
		param{key: "a2", val: "r b"},
		param{key: "oauth_consumer_key", val: "9djdj82h48djs9d2"},
		param{key: "oauth_token", val: "kkk9d7dh3k39sjv7"},
		param{key: "oauth_signature_method", val: "HMAC-SHA1"},
		param{key: "oauth_timestamp", val: "137131201"},
		param{key: "oauth_nonce", val: "7d8f3e4a"},
		param{key: "c2", val: ""},
		param{key: "a3", val: "2 q"},
	}

	res := normalizeParams(params)

	expected := "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"

	if res != expected {
		t.Fatalf("Expected:\n%s\nGot:\n%s", expected, res)
	}
}

func TestCollectParams(t *testing.T) {
	req := rfcRequest()
	params := collectAllParams(req)

	if len(params) != 11 {
		t.Fatalf("Expected 11 params?\n%+v", params)
	}
}

func TestSignatureBaseStringFromRequest(t *testing.T) {
	req := rfcRequest()

	baseString := signatureBaseStringFromRequest(req)

	expected := "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
	if baseString != expected {
		t.Fatalf("signatureBaseString did not produce expected result. Expected:\n%s\nGot:\n%s\n", expected, baseString)
	}
}

var clientSecret = "ECrDNoq1VYzzzzzzzzzyAK7TwZNtPnkqatqZZZZ"
var resourceOwnerSecret = "just-a-string-asdasd"

func TestGenerateSignatureHmacSHA1(t *testing.T) {
	// Control signature created using openssl:
	// echo -n <signatureBaseString of rfcRequest> | openssl dgst -binary -hmac <key> | base64
	expected := "oZEokHqlIM3V7wI4SSanpOp6E+8="

	res, _ := generateSignatureHmacSHA1(signatureBaseStringFromRequest(rfcRequest()), clientSecret, resourceOwnerSecret)
	if res != expected {
		t.Fatalf("\nExpected:\n%s\nGot:\n%s\n", expected, res)
	}
}

func TestGenerateSignaturePlaintext(t *testing.T) {
	expected := fmt.Sprintf("%s&%s", clientSecret, resourceOwnerSecret)

	res, _ := generateSignaturePlaintext(clientSecret, resourceOwnerSecret)
	if res != expected {
		t.Fatalf("\nExpected:\n%s\nGot:\n%s\n", expected, res)
	}
}

// openssl genrsa -out <key>.pem 1024
var rsaKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC5SChqvNflIFI6+t45VM9/1T15RUkeRri535wGAQWuUL6E5w/+
gSWuw41caYpn7Ox3kUAC/V1II40zCbY2l8DcT6sg72oMZ5Kw5MDsPdcVtyubRY6F
deJIB57jpK+BWqMM1ySX7AUKRijHL6sLety+rSKVavCudlW1ldwefqBkiQIDAQAB
AoGBAKGcOwS/K2GDy7X+VA+V1lgeW7yHnrt13HLkhGcIRThC3at3EBBh/chuccMF
m+ACXE/+teLltJPTzrmR4wnDXEhRP4FVcpAEHdOeVuiO3v7RGj7xl4WWHxuhasPb
iWo412zfBbiyZdeyyXHzH7xRZy6iZeEM88OdZ42hh1TrhAgxAkEA7NoGQgjR/u2O
73JdLBH2f20JXPuBJXVVkM2L/1NekxBbi1uuxT8F3p9xQtY3UYcK1M9UXxInXHFT
/Rlh+0Q2ywJBAMhC0xvsdlW8+f4lDvsX+00OezaFsWdaAT2FIhex/J0uvwZOHaev
RpduhBpuZxBdo1JidwrhX5jP5IVNbbw7E3sCQG2AQuJmp4d/ltSXAAJu75Jr+6c0
U7nYrE186huKFLBTIK+mHH/uqi0Jc9idpweXMme+ztgBUZdIgbcC9Cyxlc8CQQCT
dWk/eXmVHmayNZV3XKxFjDE772u233ZkV2DIM93/24j7Wo/Jhm2jWdRaJgsr6Nc2
9ZwUXelne0UYxu/Tl2h7AkEA51ETEaJjkXnpqsnG68B+RUakUGyitEE3arLIckjF
FYwgVMzFe8JzoQtBVe2vntRDNhyG+lzBurbNOXfvakkIaA==
-----END RSA PRIVATE KEY-----
`)

func TestGenerateSignatureRSAHappy(t *testing.T) {
	// Control signature created using openssl:
	// echo -n <signatureBaseString of rfcRequest> | openssl dgst -sha1 -sign <key>.pem | base64
	expected := "P29VluAE78dGR9T7d5OS1p/X8oUQJet7+8z7C14Y4FnvTSbL38mScNm0R3+f3MFdhYnFT4SCnKBUo3a8bwrFBXk38LiKTUbQbvZo44Vvas+N6AYuurQp9yNWvhEBurqxYL8EHXWG1hDrW417em0F7l7GykQyyY9SfD869QdTBis="

	res, err := generateSignatureRsaSHA1(signatureBaseStringFromRequest(rfcRequest()), rsaKey)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if res != expected {
		t.Fatalf("\nExpected:\n%s\nGot:\n%s\n", expected, res)
	}
}

func TestGenerateSignatureRSAFailures(t *testing.T) {
	// no private key
	_, err := generateSignatureRsaSHA1(signatureBaseStringFromRequest(rfcRequest()), []byte(""))
	if err == nil || err.Error() != "oauth1: need to provide valid rsa private key in order to sign with RSA-SHA1" {
		t.Fatalf("Expected an error thrown when rsa private key is nil: %s", err.Error())
	}
}
