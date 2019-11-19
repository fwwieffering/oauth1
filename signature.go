package oauth1

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func collectAllParams(req *http.Request) []param {
	//    o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
	//       present.  The header's content is parsed into a list of name/value
	//       pairs excluding the "realm" parameter if present.  The parameter
	//       values are decoded as defined by Section 3.5.1.
	//    The "oauth_signature" parameter MUST be excluded from the signature
	//    base string if present.  Parameters not explicitly included in the
	//    request MUST be excluded from the signature base string (e.g., the
	//    "oauth_version" parameter when omitted).
	oauthParams := oauthParamsFromHeader(req.Header.Get("authorization"))
	oauthParams.Signature = ""
	return collectParams(req, oauthParams)
}

// collectParams collects the parameters for the signature base string from a request
func collectParams(req *http.Request, oauth oauthParams) []param {
	//    The parameters from the following sources are collected into a single
	//    list of name/value pairs:

	//    o  The query component of the HTTP request URI as defined by
	//       [RFC3986], Section 3.4.  The query component is parsed into a list
	//       of name/value pairs by treating it as an
	//       "application/x-www-form-urlencoded" string, separating the names
	//       and values and decoding them as defined by
	//       [W3C.REC-html40-19980424], Section 17.13.4.
	queryParams := req.URL.Query()

	//    o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
	//       present.  The header's content is parsed into a list of name/value
	//       pairs excluding the "realm" parameter if present.  The parameter
	//       values are decoded as defined by Section 3.5.1.
	//    The "oauth_signature" parameter MUST be excluded from the signature
	//    base string if present.  Parameters not explicitly included in the
	//    request MUST be excluded from the signature base string (e.g., the
	//    "oauth_version" parameter when omitted).

	// these are generated and passed to the function
	oauthParamList := oauth.toMap()

	//    o  The HTTP request entity-body, but only if all of the following
	//       conditions are met:
	//       *  The entity-body is single-part.
	//       *  The entity-body follows the encoding requirements of the
	//          "application/x-www-form-urlencoded" content-type as defined by
	//          [W3C.REC-html40-19980424].
	//       *  The HTTP request entity-header includes the "Content-Type"
	//          header field set to "application/x-www-form-urlencoded".
	bodyParams := parseFormBody(req)

	merged := mergeParams(oauthParamList, queryParams, bodyParams)

	return merged
}

// 3.4.1.3.2.  Parameters Normalization
//    For example, the list of parameters from the previous section would
//    be normalized as follows:
//                                  Encoded:
//                +------------------------+------------------+
//                |          Name          |       Value      |
//                +------------------------+------------------+
//                |           b5           |     %3D%253D     |
//                |           a3           |         a        |
//                |          c%40          |                  |
//                |           a2           |       r%20b      |
//                |   oauth_consumer_key   | 9djdj82h48djs9d2 |
//                |       oauth_token      | kkk9d7dh3k39sjv7 |
//                | oauth_signature_method |     HMAC-SHA1    |
//                |     oauth_timestamp    |     137131201    |
//                |       oauth_nonce      |     7d8f3e4a     |
//                |           c2           |                  |
//                |           a3           |       2%20q      |
//                +------------------------+------------------+
//                                   Sorted:
//                +------------------------+------------------+
//                |          Name          |       Value      |
//                +------------------------+------------------+
//                |           a2           |       r%20b      |
//                |           a3           |       2%20q      |
//                |           a3           |         a        |
//                |           b5           |     %3D%253D     |
//                |          c%40          |                  |
//                |           c2           |                  |
//                |   oauth_consumer_key   | 9djdj82h48djs9d2 |
//                |       oauth_nonce      |     7d8f3e4a     |
//                | oauth_signature_method |     HMAC-SHA1    |
//                |     oauth_timestamp    |     137131201    |
//                |       oauth_token      | kkk9d7dh3k39sjv7 |
//                +------------------------+------------------+
//                             Concatenated Pairs:
//                   +-------------------------------------+
//                   |              Name=Value             |
//                   +-------------------------------------+
//                   |               a2=r%20b              |
//                   |               a3=2%20q              |
//                   |                 a3=a                |
//                   |             b5=%3D%253D             |
//                   |                c%40=                |
//                   |                 c2=                 |
//                   | oauth_consumer_key=9djdj82h48djs9d2 |
//                   |         oauth_nonce=7d8f3e4a        |
//                   |   oauth_signature_method=HMAC-SHA1  |
//                   |      oauth_timestamp=137131201      |
//                   |     oauth_token=kkk9d7dh3k39sjv7    |
//                   +-------------------------------------+
//    and concatenated together into a single string (line breaks are for
//    display purposes only):

//      a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
//      dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
//      &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7
func normalizeParams(params []param) string {
	//    1.  First, the name and value of each parameter are encoded
	//        (Section 3.6).
	for i := range params {
		params[i].encode()
	}
	//    2.  The parameters are sorted by name, using ascending byte value
	//        ordering.  If two or more parameters share the same name, they
	//        are sorted by their value.
	sort.Slice(params, func(i, j int) bool {
		if params[i].key == params[j].key {
			return params[i].val < params[j].val
		}
		return params[i].key < params[j].key
	})
	//    3.  The name of each parameter is concatenated to its corresponding
	//        value using an "=" character (ASCII code 61) as a separator, even
	//        if the value is empty.
	paramStrs := make([]string, len(params))
	for i := range params {
		paramStrs[i] = params[i].display()
	}
	//    4.  The sorted name/value pairs are concatenated together into a
	//        single string by using an "&" character (ASCII code 38) as
	//        separator.
	return strings.Join(paramStrs, "&")
}

// generateSignature
func generateSignature(params []param, baseURI string, httpMethod string, signatureMethod SignatureMethod, clientCreds *Credentials, resourceOwnerCreds *Credentials, rsaKey []byte) (string, error) {
	baseString := signatureBaseStringFromParams(params, baseURI, httpMethod)
	switch signatureMethod {
	case Plaintext:
		return generateSignaturePlaintext(clientCreds.TokenSecret, resourceOwnerCreds.TokenSecret)
	case RsaSha1:
		return generateSignatureRsaSHA1(baseString, rsaKey)
	case HmacSha1:
		return generateSignatureHmacSHA1(baseString, clientCreds.TokenSecret, resourceOwnerCreds.TokenSecret)
	default:
		return "", fmt.Errorf("oauth1: unknown signature method")
	}
}

func signatureBaseStringFromParams(params []param, baseURI string, httpMethod string) string {
	return fmt.Sprintf(
		"%s&%s&%s",
		httpMethod,
		escape(baseURI),
		escape(normalizeParams(params)),
	)
}

// _3.4.1.1
// For example, the HTTP request:
//   POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
//   Host: example.com
//   Content-Type: application/x-www-form-urlencoded
//   Authorization: OAuth realm="Example",
// 				 oauth_consumer_key="9djdj82h48djs9d2",
// 				 oauth_token="kkk9d7dh3k39sjv7",
// 				 oauth_signature_method="HMAC-SHA1",
// 				 oauth_timestamp="137131201",
// 				 oauth_nonce="7d8f3e4a",
// 				 oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
//
//   c2&a3=2+q
//
// is represented by the following signature base string (line breaks
// are for display purposes only):
//
//   POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
//   %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
//   key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
//   ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
//   9d7dh3k39sjv7
func signatureBaseStringFromRequest(req *http.Request) string {
	// The signature base string is constructed by concatenating together,
	// in order, the following HTTP request elements:
	// 1.  The HTTP request method in uppercase.  For example: "HEAD",
	// 	"GET", "POST", etc.  If the request uses a custom HTTP method, it
	// 	MUST be encoded (Section 3.6).
	baseStr := req.Method
	// 2.  An "&" character (ASCII code 38).
	baseStr += "&"
	// 3.  The base string URI from Section 3.4.1.2, after being encoded
	// 	(Section 3.6).

	// request could be server side or client side. if server side, values have to be pulled from different
	// fields
	var uri string
	if req.RequestURI != "" {
		scheme := "https"
		if req.TLS == nil {
			scheme = "http"
		}
		parsedHost, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, req.Host))
		uri = getBaseStrURI(scheme, parsedHost.Hostname(), parsedHost.Port(), req.URL.EscapedPath())
	} else {
		uri = getBaseStrURI(req.URL.Scheme, req.URL.Host, req.URL.Port(), req.URL.EscapedPath())
	}
	baseStr += escape(uri)
	// 4.  An "&" character (ASCII code 38).
	baseStr += "&"
	// 5.  The request parameters as normalized in Section 3.4.1.3.2, after
	// 	being encoded (Section 3.6).
	baseStr += escape(normalizeParams(collectAllParams(req)))
	return baseStr
}

// signHmacSHA1 signs request according to the HMAC-SHA1 protocol defined in 3.4.2
// The "HMAC-SHA1" signature method uses the HMAC-SHA1 signature
// algorithm as defined in [RFC2104]:
//
//   digest = HMAC-SHA1 (key, text)
//
// The HMAC-SHA1 function variables are used in following way:
//
// text    is set to the value of the signature base string from
// 		Section 3.4.1.1.
//
// key     is set to the concatenated values of:
//
// 		1.  The client shared-secret, after being encoded
// 			(Section 3.6).
// 		2.  An "&" character (ASCII code 38), which MUST be included
// 			even when either secret is empty.
// 		3.  The token shared-secret, after being encoded
// 			(Section 3.6).
// digest  is used to set the value of the "oauth_signature" protocol
// 		parameter, after the result octet string is base64-encoded
// 		per [RFC2045], Section 6.8.
func generateSignatureHmacSHA1(signatureBaseString string, clientSecret string, resourceOwnerSecret string) (string, error) {
	clientSharedSecret := escape(clientSecret)
	tokenSharedSecret := escape(resourceOwnerSecret)

	key := fmt.Sprintf("%s&%s", clientSharedSecret, tokenSharedSecret)

	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(signatureBaseString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// signPlaintext signs the request according to the PLAINTEXT protocol defined in 3.4.4
// The "PLAINTEXT" method does not employ a signature algorithm.  It
// MUST be used with a transport-layer mechanism such as TLS or SSL (or
// sent over a secure channel with equivalent protections).  It does not
// utilize the signature base string or the "oauth_timestamp" and
// "oauth_nonce" parameters.

// The "oauth_signature" protocol parameter is set to the concatenated
// value of:

// 1.  The client shared-secret, after being encoded (Section 3.6).

// 2.  An "&" character (ASCII code 38), which MUST be included even
// 	when either secret is empty.

// 3.  The token shared-secret, after being encoded (Section 3.6).
func generateSignaturePlaintext(clientSecret string, resourceOwnerSecret string) (string, error) {
	return fmt.Sprintf("%s&%s", escape(clientSecret), escape(resourceOwnerSecret)), nil
}

// The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
// algorithm as defined in [RFC3447], Section 8.2 (also known as
// PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
// use this method, the client MUST have established client credentials
// with the server that included its RSA public key (in a manner that is
// beyond the scope of this specification).
// The signature base string is signed using the client's RSA private
// key per [RFC3447], Section 8.2.1:
//   S = RSASSA-PKCS1-V1_5-SIGN (K, M)
// Where:
// K     is set to the client's RSA private key,
// M     is set to the value of the signature base string from
// 	  Section 3.4.1.1, and
// 	  S     is the result signature used to set the value of the
// 	  "oauth_signature" protocol parameter, after the result octet
// 	  string is base64-encoded per [RFC2045] section 6.8.
// The server verifies the signature per [RFC3447] section 8.2.2:
//   RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)
// Where:
// (n, e) is set to the client's RSA public key,
// M      is set to the value of the signature base string from
// 	   Section 3.4.1.1, and
// S      is set to the octet string value of the "oauth_signature"
// 	   protocol parameter received from the client.
func generateSignatureRsaSHA1(signatureBaseString string, rsaPrivateKey []byte) (string, error) {
	block, _ := pem.Decode(rsaPrivateKey)
	if block == nil {
		return "", fmt.Errorf("oauth1: need to provide valid rsa private key in order to sign with RSA-SHA1")
	}
	// TODO: maybe the format of this private key needs to be checked
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("oauth1: error parsing private key %s", err.Error())
	}

	h := sha1.New()
	h.Write([]byte(signatureBaseString))
	sum := h.Sum(nil)

	sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA1, sum)

	return base64.StdEncoding.EncodeToString(sig), nil
}
