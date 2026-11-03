package gatesvc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/deepnavakoti/acra/internal/valkey"
)

// EpochStore holds the per-task epoch fence. The fence only moves forward.
// Implementations must be safe for concurrent use. A store error must never be
// read as "epoch 0": the service holds the write instead (fail closed).
type EpochStore interface {
	// Get returns the current epoch for task (0 when never set).
	Get(ctx context.Context, task string) (int, error)
	// Advance sets the epoch if it is >= the current one. It returns the epoch in
	// force afterwards and whether the request was accepted.
	Advance(ctx context.Context, task string, epoch int) (current int, accepted bool, err error)
}

const maxTaskLen = 200

func checkTask(task string) error {
	if task == "" || len(task) > maxTaskLen {
		return fmt.Errorf("gate: task must be 1..%d bytes", maxTaskLen)
	}
	return nil
}

// MemoryEpochs keeps epochs in process memory. They are lost on restart, which
// resets the fence: use ValkeyEpochs when that matters.
type MemoryEpochs struct {
	mu sync.Mutex
	m  map[string]int
}

// NewMemoryEpochs returns an empty in-memory store.
func NewMemoryEpochs() *MemoryEpochs { return &MemoryEpochs{m: map[string]int{}} }

func (s *MemoryEpochs) Get(_ context.Context, task string) (int, error) {
	if err := checkTask(task); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[task], nil
}

func (s *MemoryEpochs) Advance(_ context.Context, task string, epoch int) (int, bool, error) {
	if err := checkTask(task); err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.m[task]; epoch < cur {
		return cur, false, nil
	}
	s.m[task] = epoch
	return epoch, true, nil
}

// ValkeyEpochs keeps epochs in Valkey so the fence survives gate restarts and is
// shared by every gate replica. Advance is one atomic server-side script, so two
// replicas cannot move the fence backwards by racing.
type ValkeyEpochs struct {
	C      *valkey.Client
	Prefix string // default "acra:gate:epoch:"
}

const advanceScript = `
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local want = tonumber(ARGV[1])
if want < cur then return {0, cur} end
redis.call('SET', KEYS[1], ARGV[1])
return {1, want}
`

func (s *ValkeyEpochs) key(task string) string {
	p := s.Prefix
	if p == "" {
		p = "acra:gate:epoch:"
	}
	return p + task
}

func (s *ValkeyEpochs) Get(ctx context.Context, task string) (int, error) {
	if err := checkTask(task); err != nil {
		return 0, err
	}
	v, err := s.C.Get(ctx, s.key(task))
	if errors.Is(err, valkey.ErrNil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		// A corrupt value must not read as 0, which would reopen the fence.
		return 0, fmt.Errorf("gate: epoch for %q is corrupt in valkey", task)
	}
	return n, nil
}

func (s *ValkeyEpochs) Advance(ctx context.Context, task string, epoch int) (int, bool, error) {
	if err := checkTask(task); err != nil {
		return 0, false, err
	}
	if epoch < 0 {
		return 0, false, errors.New("gate: epoch must be non-negative")
	}
	r, err := s.C.Eval(ctx, advanceScript, []string{s.key(task)}, epoch)
	if err != nil {
		return 0, false, err
	}
	arr, ok := r.([]any)
	if !ok || len(arr) != 2 {
		return 0, false, fmt.Errorf("gate: unexpected script reply %v", r)
	}
	acc, ok1 := arr[0].(int64)
	cur, ok2 := arr[1].(int64)
	if !ok1 || !ok2 {
		return 0, false, fmt.Errorf("gate: unexpected script reply %v", r)
	}
	return int(cur), acc == 1, nil
}
