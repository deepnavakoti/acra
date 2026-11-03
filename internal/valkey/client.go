// Package valkey is a minimal RESP2 client for Valkey (and Redis-compatible
// servers), written against the standard library so ACRA adds no dependency.
// It supports only what ACRA needs: AUTH, PING, GET, SET, DEL and EVAL, over
// plain TCP or TLS, with a small connection pool and a deadline on every
// command. It is not a general-purpose client: no pub/sub, pipelining, cluster
// redirects or sentinel.
package valkey

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBulk    = 1 << 20 // refuse replies larger than 1 MiB
	maxArray   = 1024
	maxLineLen = 4096
	poolSize   = 4
)

// ErrNil is returned for a nil bulk reply (a missing key).
var ErrNil = errors.New("valkey: nil reply")

// ServerError is an error reply from the server (for example WRONGPASS).
type ServerError string

func (e ServerError) Error() string { return "valkey: server error: " + string(e) }

// Client is safe for concurrent use.
type Client struct {
	addr     string
	useTLS   bool
	password string
	username string
	timeout  time.Duration
	tlsCfg   *tls.Config

	mu   sync.Mutex
	idle []*conn
}

type conn struct {
	nc net.Conn
	br *bufio.Reader
}

// Options configure a Client. The password is passed separately from the URL so
// it never appears in logs or in a rendered manifest.
type Options struct {
	URL      string // valkey://host:6379, redis://host:6379 or rediss://host:6379 (TLS)
	Username string
	Password string
	Timeout  time.Duration // per command, default 2s
	TLS      *tls.Config   // optional override for rediss://
}

// New validates the URL and returns a Client. It does not connect.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, fmt.Errorf("valkey: invalid url: %w", err)
	}
	var useTLS bool
	switch u.Scheme {
	case "valkey", "redis":
	case "valkeys", "rediss":
		useTLS = true
	default:
		return nil, fmt.Errorf("valkey: unsupported scheme %q (use valkey, redis or rediss)", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("valkey: do not embed credentials in the url; use the username/password options")
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("valkey: url has no host")
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	to := o.Timeout
	if to <= 0 {
		to = 2 * time.Second
	}
	cfg := o.TLS
	if useTLS && cfg == nil {
		cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	return &Client{addr: net.JoinHostPort(host, port), useTLS: useTLS, username: o.Username,
		password: o.Password, timeout: to, tlsCfg: cfg}, nil
}

// Close closes pooled connections.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.idle {
		_ = k.nc.Close()
	}
	c.idle = nil
}

func (c *Client) dial(ctx context.Context) (*conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	if c.useTLS {
		tc := tls.Client(nc, c.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(c.timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = nc.Close()
			return nil, err
		}
		nc = tc
	}
	k := &conn{nc: nc, br: bufio.NewReader(nc)}
	if c.password != "" {
		args := []any{"AUTH"}
		if c.username != "" {
			args = append(args, c.username)
		}
		args = append(args, c.password)
		if _, err := c.roundTrip(k, args); err != nil {
			_ = nc.Close()
			return nil, err
		}
	}
	return k, nil
}

func (c *Client) get(ctx context.Context) (*conn, error) {
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		k := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return k, nil
	}
	c.mu.Unlock()
	return c.dial(ctx)
}

func (c *Client) put(k *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.idle) >= poolSize {
		_ = k.nc.Close()
		return
	}
	c.idle = append(c.idle, k)
}

// Do runs one command. Connection-level errors discard the connection; a server
// error reply keeps it. The reply is one of: string, int64, []any, nil.
func (c *Client) Do(ctx context.Context, args ...any) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("valkey: empty command")
	}
	k, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	rep, err := c.roundTrip(k, args)
	var se ServerError
	if err != nil && !errors.As(err, &se) {
		_ = k.nc.Close()
		return nil, err
	}
	c.put(k)
	return rep, err
}

func (c *Client) roundTrip(k *conn, args []any) (any, error) {
	_ = k.nc.SetDeadline(time.Now().Add(c.timeout))
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		s := fmt.Sprint(a)
		b.WriteString("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n")
	}
	if _, err := io.WriteString(k.nc, b.String()); err != nil {
		return nil, err
	}
	return readReply(k.br)
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLineLen {
		return "", errors.New("valkey: reply line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readReply(br *bufio.Reader) (any, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, errors.New("valkey: empty reply")
	}
	body := line[1:]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, ServerError(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, fmt.Errorf("valkey: bad bulk length %q", body)
		}
		if n < 0 {
			return nil, nil
		}
		if n > maxBulk {
			return nil, errors.New("valkey: bulk reply too large")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, fmt.Errorf("valkey: bad array length %q", body)
		}
		if n < 0 {
			return nil, nil
		}
		if n > maxArray {
			return nil, errors.New("valkey: array reply too large")
		}
		out := make([]any, n)
		for i := range out {
			v, err := readReply(br)
			if err != nil {
				var se ServerError
				if errors.As(err, &se) {
					out[i] = se
					continue
				}
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("valkey: unexpected reply type %q", line[0])
}

// Ping checks connectivity and credentials.
func (c *Client) Ping(ctx context.Context) error {
	r, err := c.Do(ctx, "PING")
	if err != nil {
		return err
	}
	if s, _ := r.(string); s != "PONG" {
		return fmt.Errorf("valkey: unexpected PING reply %v", r)
	}
	return nil
}

// Get returns the string value, or ErrNil when the key is absent.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	r, err := c.Do(ctx, "GET", key)
	if err != nil {
		return "", err
	}
	if r == nil {
		return "", ErrNil
	}
	s, ok := r.(string)
	if !ok {
		return "", fmt.Errorf("valkey: GET returned %T", r)
	}
	return s, nil
}

// Eval runs a Lua script.
func (c *Client) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	cmd := []any{"EVAL", script, len(keys)}
	for _, k := range keys {
		cmd = append(cmd, k)
	}
	cmd = append(cmd, args...)
	return c.Do(ctx, cmd...)
}
