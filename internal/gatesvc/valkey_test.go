package gatesvc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/deepnavakoti/acra/internal/detectors"
	"github.com/deepnavakoti/acra/internal/gate"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/model"
	"github.com/deepnavakoti/acra/internal/valkey"
)

// fakeValkey is a tiny RESP server that emulates the commands ACRA uses. It is
// NOT a real Valkey: it implements the advance script's documented semantics
// directly, so these tests prove the client protocol and the service behaviour,
// not the Lua script itself.
type fakeValkey struct {
	ln       net.Listener
	mu       sync.Mutex
	data     map[string]string
	password string
	down     bool
	corrupt  bool
}

func newFake(t *testing.T, password string) *fakeValkey {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeValkey{ln: ln, data: map[string]string{}, password: password}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeValkey) url() string { return "valkey://" + f.ln.Addr().String() }

func (f *fakeValkey) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func readCmd(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sz, _ := strconv.Atoi(strings.TrimSpace(l[1:]))
		buf := make([]byte, sz+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:sz]))
	}
	return out, nil
}

func (f *fakeValkey) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	authed := f.password == ""
	for {
		cmd, err := readCmd(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		down, corrupt := f.down, f.corrupt
		f.mu.Unlock()
		if down {
			return // drop the connection
		}
		switch strings.ToUpper(cmd[0]) {
		case "AUTH":
			if cmd[len(cmd)-1] == f.password {
				authed = true
				fmt.Fprint(c, "+OK\r\n")
			} else {
				fmt.Fprint(c, "-WRONGPASS invalid password\r\n")
			}
		case "PING":
			if !authed {
				fmt.Fprint(c, "-NOAUTH Authentication required\r\n")
				continue
			}
			fmt.Fprint(c, "+PONG\r\n")
		case "GET":
			if !authed {
				fmt.Fprint(c, "-NOAUTH Authentication required\r\n")
				continue
			}
			f.mu.Lock()
			v, ok := f.data[cmd[1]]
			f.mu.Unlock()
			switch {
			case corrupt:
				fmt.Fprint(c, "$3\r\nabc\r\n")
			case !ok:
				fmt.Fprint(c, "$-1\r\n")
			default:
				fmt.Fprintf(c, "$%d\r\n%s\r\n", len(v), v)
			}
		case "EVAL":
			if !authed {
				fmt.Fprint(c, "-NOAUTH Authentication required\r\n")
				continue
			}
			key, want := cmd[3], cmd[4]
			w, _ := strconv.Atoi(want)
			f.mu.Lock()
			cur, _ := strconv.Atoi(f.data[key])
			if w < cur {
				f.mu.Unlock()
				fmt.Fprintf(c, "*2\r\n:0\r\n:%d\r\n", cur)
				continue
			}
			f.data[key] = want
			f.mu.Unlock()
			fmt.Fprintf(c, "*2\r\n:1\r\n:%d\r\n", w)
		default:
			fmt.Fprint(c, "-ERR unknown command\r\n")
		}
	}
}

func valkeyEpochs(t *testing.T, f *fakeValkey, password string) *ValkeyEpochs {
	t.Helper()
	c, err := valkey.New(valkey.Options{URL: f.url(), Password: password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &ValkeyEpochs{C: c}
}

func svcWith(es EpochStore) *Service {
	pol := gate.Policy{
		ApprovedTuples:      []model.Tuple{{Prompt: "p-30", Manifest: "1.8.3", Ruleset: "e8d3", Formula: "f-6"}},
		MinIndependentRoots: 2,
	}
	s := New(pol, detectors.Default(), identity.New(nil), nil)
	s.Epochs = es
	return s
}

func TestValkeyEpochsMonotonic(t *testing.T) {
	f := newFake(t, "")
	es := valkeyEpochs(t, f, "")
	ctx := context.Background()
	if n, err := es.Get(ctx, "t1"); err != nil || n != 0 {
		t.Fatalf("unset epoch = %d, %v", n, err)
	}
	if cur, ok, err := es.Advance(ctx, "t1", 8); err != nil || !ok || cur != 8 {
		t.Fatalf("advance: %d %v %v", cur, ok, err)
	}
	if cur, ok, err := es.Advance(ctx, "t1", 3); err != nil || ok || cur != 8 {
		t.Fatalf("decrease must be rejected: %d %v %v", cur, ok, err)
	}
	if _, ok, _ := es.Advance(ctx, "t1", 8); !ok {
		t.Fatal("re-asserting the same epoch is allowed")
	}
}

func TestValkeyEpochsSurviveGateRestart(t *testing.T) {
	f := newFake(t, "")
	s1 := svcWith(valkeyEpochs(t, f, ""))
	if code, _ := post(s1, "/v1/gate/epochs/t1", "PUT", `{"epoch":8}`, ""); code != http.StatusOK {
		t.Fatalf("set epoch: %d", code)
	}
	// A new Service (a restarted or second replica) sees the same fence.
	s2 := svcWith(valkeyEpochs(t, f, ""))
	_, out := post(s2, "/v1/gate/evaluate", "POST", `{"task":"t1","epoch":5,`+approved+`}`, "")
	if !strings.Contains(out, "HOLD") {
		t.Fatalf("stale epoch must HOLD after restart: %s", out)
	}
	if code, _ := post(s2, "/v1/gate/epochs/t1", "PUT", `{"epoch":2}`, ""); code != http.StatusConflict {
		t.Fatalf("epoch must not decrease across replicas, got %d", code)
	}
}

func TestValkeyDownFailsClosed(t *testing.T) {
	f := newFake(t, "")
	s := svcWith(valkeyEpochs(t, f, ""))
	if code, _ := post(s, "/v1/gate/epochs/t1", "PUT", `{"epoch":1}`, ""); code != http.StatusOK {
		t.Fatal("setup failed")
	}
	f.setDown(true)
	// Even a write at a huge epoch is held: the fence is unknown.
	_, out := post(s, "/v1/gate/evaluate", "POST", `{"task":"t1","epoch":999999,`+approved+`}`, "")
	if !strings.Contains(out, "HOLD") {
		t.Fatalf("store outage must HOLD, never ADMIT: %s", out)
	}
	if code, _ := post(s, "/v1/gate/epochs/t1", "PUT", `{"epoch":5}`, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("epoch update during outage must be 503, got %d", code)
	}
}

func TestCorruptEpochValueFailsClosed(t *testing.T) {
	f := newFake(t, "")
	f.mu.Lock()
	f.corrupt = true
	f.mu.Unlock()
	s := svcWith(valkeyEpochs(t, f, ""))
	_, out := post(s, "/v1/gate/evaluate", "POST", `{"task":"t1","epoch":7,`+approved+`}`, "")
	if !strings.Contains(out, "HOLD") {
		t.Fatalf("corrupt epoch must HOLD: %s", out)
	}
}

func TestValkeyAuth(t *testing.T) {
	f := newFake(t, "s3cret-pass-0123")
	if _, _, err := valkeyEpochs(t, f, "wrong").Advance(context.Background(), "t", 1); err == nil {
		t.Fatal("wrong password must fail")
	}
	if _, ok, err := valkeyEpochs(t, f, "s3cret-pass-0123").Advance(context.Background(), "t", 1); err != nil || !ok {
		t.Fatalf("right password: %v %v", ok, err)
	}
}

func TestValkeyURLValidation(t *testing.T) {
	for _, u := range []string{"http://x:1", "valkey://user:pw@x:1", "valkey://", "::bad"} {
		if _, err := valkey.New(valkey.Options{URL: u}); err == nil {
			t.Errorf("url %q must be rejected", u)
		}
	}
	if _, err := valkey.New(valkey.Options{URL: "rediss://valkey.ns.svc:6379"}); err != nil {
		t.Errorf("rediss url: %v", err)
	}
}

func TestMemoryEpochsRejectsBadTask(t *testing.T) {
	m := NewMemoryEpochs()
	if _, _, err := m.Advance(context.Background(), strings.Repeat("x", 300), 1); err == nil {
		t.Fatal("oversize task must be rejected")
	}
}
