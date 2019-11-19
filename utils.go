package oauth1

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var seededRand *rand.Rand
var nonceCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func init() {
	seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// nonce generates random 32 byte nonce
func nonce() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = nonceCharSet[seededRand.Intn(32)]
	}
	return string(b)
}

// timestamp produces the oauth_timestamp parameter value
// The timestamp value MUST be a positive integer.  Unless otherwise
//    specified by the server's documentation, the timestamp is expressed
//    in the number of seconds since January 1, 1970 00:00:00 GMT.
func timestamp() string {
	t := time.Now()
	return strconv.FormatInt(t.Unix(), 10)
}

// escape
func escape(s string) string {
	e := url.QueryEscape(s)
	// queryEscape works but encodes " " as "+"
	// so replace + with "%20 after query escape"
	return strings.ReplaceAll(e, "+", "%20")
}

func unescape(s string) string {
	u, _ := url.PathUnescape(s)
	return u
}

// example oauth header
// Authorization: OAuth realm="Photos",
//         oauth_consumer_key="dpf43f3p2l4k3l03",
//         oauth_token="nnch734d00sl2jdk",
//         oauth_signature_method="HMAC-SHA1",
//         oauth_timestamp="137131202",
//         oauth_nonce="chapoH",
//         oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"
func parseOauthHeader(authHeader string) map[string][]string {
	if !strings.HasPrefix(strings.ToLower(authHeader), "oauth ") {
		return map[string][]string{}
	}
	groupCatcher, _ := regexp.Compile(`(([a-zA-Z0-9_]*)=("[^"]*"))`)

	groups := groupCatcher.FindAllString(authHeader, -1)

	params := make(map[string][]string)

	for _, group := range groups {
		splitGroup := strings.Split(group, "=")
		key := splitGroup[0]
		// value could contain =, rejoin.
		val := strings.Trim(strings.Join(splitGroup[1:], "="), "\"")
		params[key] = []string{unescape(val)}
	}

	return params
}

func parseFormBody(req *http.Request) map[string][]string {
	if req.Body != nil && req.Header.Get("content-type") == "application/x-www-form-urlencoded" {
		// read body and immediately restore it
		b, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		// parse form body
		vals, err := url.ParseQuery(string(b))
		if err != nil {
			return nil
		}
		return vals
	}
	return nil
}

func mergeParams(firstmap map[string][]string, next ...map[string][]string) []param {
	res := make([]param, 0)
	for _, m := range append(next, firstmap) {
		for k, v := range m {
			res = append(res, param{key: k, val: strings.Join(v, "")})
		}
	}
	return res
}

func mapToParams(m map[string][]string) []param {
	params := make([]param, 0)

	for k, v := range m {
		params = append(params, param{key: k, val: v[0]})
	}
	return params
}

// 3.4.1.2.  Base String URI
//    For example, the HTTP request:
//      GET /r%20v/X?id=123 HTTP/1.1
//      Host: EXAMPLE.COM:80
//    is represented by the base string URI: "http://example.com/r%20v/X".
//    In another example, the HTTPS request:
//      GET /?q=1 HTTP/1.1
//      Host: www.example.net:8080
//    is represented by the base string URI:
//    "https://www.example.net:8080/".
func getBaseStrURI(scheme string, hostname string, port string, path string) string {
	//    The scheme, authority, and path of the request resource URI [RFC3986]
	//    are included by constructing an "http" or "https" URI representing
	//    the request resource (without the query or fragment) as follows:
	//    1.  The scheme and host MUST be in lowercase.
	//    2.  The host and port values MUST match the content of the HTTP
	//        request "Host" header field.
	lScheme := strings.ToLower(scheme)
	parsedPath, _ := url.Parse(path)
	path = strings.TrimLeft(parsedPath.EscapedPath(), "/")

	parsedHost, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, hostname))
	host := strings.TrimRight(strings.ToLower(parsedHost.Hostname()), "/")

	//    3.  The port MUST be included if it is not the default port for the
	//        scheme, and MUST be excluded if it is the default.  Specifically,
	//        the port MUST be excluded when making an HTTP request [RFC2616]
	//        to port 80 or when making an HTTPS request [RFC2818] to port 443.
	//        All other non-default port numbers MUST be included.
	if port == "" ||
		(port == "80" && lScheme == "http") || (port == "443" && lScheme == "https") {
		return fmt.Sprintf("%s://%s/%s", lScheme, host, path)
	}

	return fmt.Sprintf("%s://%s:%s/%s", lScheme, host, port, path)
}
