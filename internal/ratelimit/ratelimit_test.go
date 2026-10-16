package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New()
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if r := l.Allow("a", 60, 3); !r.Allowed {
			t.Fatalf("call %d within burst was denied", i)
		}
	}
	r := l.Allow("a", 60, 3)
	if r.Allowed {
		t.Fatal("call beyond burst was allowed")
	}
	if r.RetryAfter != time.Second {
		t.Errorf("retry after = %v, want 1s at 60/min", r.RetryAfter)
	}
	// Other keys have their own bucket.
	if !l.Allow("b", 60, 3).Allowed {
		t.Fatal("independent key was limited")
	}
	now = now.Add(time.Second)
	if !l.Allow("a", 60, 3).Allowed {
		t.Fatal("token did not refill after 1s")
	}
	if l.Allow("a", 60, 3).Allowed {
		t.Fatal("refilled more than one token")
	}
	// Refill never exceeds the burst.
	now = now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		l.Allow("a", 60, 3)
	}
	if l.Allow("a", 60, 3).Allowed {
		t.Fatal("bucket exceeded its capacity")
	}
}

func TestUnlimited(t *testing.T) {
	l := New()
	for i := 0; i < 1000; i++ {
		if !l.Allow("a", 0, 0).Allowed {
			t.Fatal("per_minute 0 should mean unlimited")
		}
	}
}

func TestSweepDropsOnlyRefilledBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := New()
	l.now = func() time.Time { return now }
	l.Allow("fast", 60, 1)   // refills in 1s
	l.Allow("slow", 0.01, 1) // refills in 100 minutes
	now = now.Add(11 * time.Minute)
	l.Allow("other", 60, 100)
	for l.calls%1024 != 0 { // run until the next sweep
		l.Allow("other", 60, 100)
	}
	if _, ok := l.buckets["fast"]; ok {
		t.Error("idle, refilled bucket was kept")
	}
	if _, ok := l.buckets["slow"]; !ok {
		t.Error("bucket still refilling was dropped, which would reset its limit")
	}
}
