// Package ratelimit implements keyed token buckets.
//
// Buckets live in process memory, which is correct for a single gateway
// replica. Running several replicas needs a shared store (Redis with a Lua
// token bucket is the usual choice) so an agent cannot multiply its quota by
// the replica count. The Limiter interface in the gateway is the seam for that.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter holds one token bucket per key.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
	calls   int
	idleTTL time.Duration
}

type bucket struct {
	tokens   float64
	last     time.Time
	rate     float64 // tokens per second, as of the last call
	capacity float64
}

// New returns an empty limiter.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: time.Now, idleTTL: 10 * time.Minute}
}

// Result describes one rate-limit check.
type Result struct {
	Allowed    bool
	Remaining  int           // whole tokens left after this call
	RetryAfter time.Duration // how long until one token is available, when denied
}

// Allow takes one token from the bucket for key. perMinute <= 0 disables the
// limit. Changing perMinute or burst for an existing key takes effect on the
// next call, which is how policy reloads reach live buckets.
func (l *Limiter) Allow(key string, perMinute float64, burst int) Result {
	if perMinute <= 0 {
		return Result{Allowed: true, Remaining: math.MaxInt32}
	}
	if burst < 1 {
		burst = 1
	}
	rate := perMinute / 60 // tokens per second
	capacity := float64(burst)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(capacity, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last, b.rate, b.capacity = now, rate, capacity

	if b.tokens >= 1 {
		b.tokens--
		return Result{Allowed: true, Remaining: int(b.tokens)}
	}
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return Result{Allowed: false, RetryAfter: wait.Round(time.Millisecond)}
}

// sweep runs every 1024 calls and drops buckets that have been idle long
// enough to refill completely, so the map cannot grow without bound. A
// dropped bucket comes back full, which is exactly what it had refilled to.
func (l *Limiter) sweep(now time.Time) {
	l.calls++
	if l.calls%1024 != 0 {
		return
	}
	for k, b := range l.buckets {
		idle := now.Sub(b.last)
		if idle > l.idleTTL && b.tokens+idle.Seconds()*b.rate >= b.capacity {
			delete(l.buckets, k)
		}
	}
}
