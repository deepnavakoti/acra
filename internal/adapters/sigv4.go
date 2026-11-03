package adapters

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWSCredentials are static or session credentials for SigV4.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional
}

// signedHeaderSet lists headers that SignV4 includes when present.
var signedHeaderSet = map[string]bool{
	"content-type": true, "x-amz-target": true, "x-amz-security-token": true,
	"x-amz-content-sha256": true,
}

// SignV4 signs req in place with AWS Signature Version 4. body must be the exact
// request body bytes (nil for none). It sets X-Amz-Date, X-Amz-Security-Token
// (when a session token exists) and Authorization. Hand-written to avoid pulling
// in a cloud SDK; verified against the public "get-vanilla" test vector.
func SignV4(req *http.Request, body []byte, c AWSCredentials, region, service string, now time.Time) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("aws: missing credentials")
	}
	if region == "" || service == "" {
		return errors.New("aws: region and service are required")
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	hdrs := map[string]string{"host": host, "x-amz-date": amzDate}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if signedHeaderSet[lk] && len(v) > 0 {
			hdrs[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
		}
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + hdrs[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	payloadHash := sha256Hex(body)
	canonical := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL.EscapedPath()),
		canonicalQuery(req.URL.Query()),
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
	return nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func awsEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func canonicalQuery(vals map[string][]string) string {
	var pairs []string
	for k, vs := range vals {
		for _, v := range vs {
			pairs = append(pairs, awsEncode(k)+"="+awsEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}
