// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Reservations are atomic: however many attempts run at once, no more than
// the budget get to the password check.
func TestShareUnlockReservationIsAtomic(t *testing.T) {
	var th failThrottle
	keys := shareUnlockKeys(7, "198.51.100.1")
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, granted := th.reserveAttempt(keys, now); granted {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != shareUnlockLimit {
		t.Fatalf("%d attempts reserved, want %d", ok, shareUnlockLimit)
	}
	// A successful attempt gives its reservation back.
	th.releaseAttempt(keys)
	if _, granted := th.reserveAttempt(keys, now); !granted {
		t.Fatal("released reservation not reusable")
	}
	// Failures use up the budget and block the client, not the share.
	th.failAttempt(keys, now)
	if wait, granted := th.reserveAttempt(keys, now); granted || wait <= 0 {
		t.Fatalf("client not blocked (wait %v)", wait)
	}
	if _, granted := th.reserveAttempt(shareUnlockKeys(7, "198.51.100.2"), now); !granted {
		t.Fatal("another client of the same share is blocked")
	}
	// The block ends with its window.
	if _, granted := th.reserveAttempt(keys, now.Add(shareUnlockBlock+time.Second)); !granted {
		t.Fatal("client still blocked after the block")
	}
}

// The share as a whole is blocked only at the higher threshold, reached by
// failures from many clients.
func TestShareUnlockShareThreshold(t *testing.T) {
	var th failThrottle
	now := time.Now()
	clients := shareUnlockShareLimit / shareUnlockLimit
	for c := 0; c < clients; c++ {
		keys := shareUnlockKeys(9, fmt.Sprintf("198.51.100.%d", c+1))
		for i := 0; i < shareUnlockLimit; i++ {
			if _, ok := th.reserveAttempt(keys, now); !ok {
				t.Fatalf("client %d attempt %d refused early", c, i)
			}
			th.failAttempt(keys, now)
		}
	}
	if _, ok := th.reserveAttempt(shareUnlockKeys(9, "203.0.113.5"), now); ok {
		t.Fatal("share not blocked after failures from many clients")
	}
	if _, ok := th.reserveAttempt(shareUnlockKeys(10, "203.0.113.5"), now); !ok {
		t.Fatal("another share is affected")
	}
}

func TestShareUnlockParallelGuessesAndPerClientBlock(t *testing.T) {
	e := newEnv(t)
	e.s.SetTrustedProxies(mustProxies(t, "127.0.0.1,::1"))
	admin := e.setup()
	lid := e.share(admin, map[string]string{"a.txt": "x"}, map[string]any{"password": "secret12"}).S("long_id")
	url := "/api/shares/" + lid + "/unlock"

	// 16 parallel wrong guesses from one client: at most the budget reach bcrypt.
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.do("POST", url, "", map[string]any{"password": "wrong"}, "X-Forwarded-For", "198.51.100.7")
			mu.Lock()
			codes[r.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > shareUnlockLimit || codes[401] == 0 || codes[401]+codes[429] != 16 {
		t.Fatalf("parallel guesses: %v (at most %d may be checked)", codes, shareUnlockLimit)
	}
	e.want(e.do("POST", url, "", map[string]any{"password": "secret12"}, "X-Forwarded-For", "198.51.100.7"), 429, "guessing client blocked")

	// Another recipient of the same share is not locked out.
	e.want(e.do("POST", url, "", map[string]any{"password": "wrong"}, "X-Forwarded-For", "203.0.113.20"), 401, "other client wrong password")
	e.want(e.do("POST", url, "", map[string]any{"password": "secret12"}, "X-Forwarded-For", "203.0.113.20"), 200, "other client unlocks")
	// IPv6 clients count per /64.
	for i := 0; i < shareUnlockLimit; i++ {
		e.want(e.do("POST", url, "", map[string]any{"password": "wrong"}, "X-Forwarded-For", fmt.Sprintf("2001:db8:1:2::%x", i+1)), 401, "v6 guess")
	}
	e.want(e.do("POST", url, "", map[string]any{"password": "secret12"}, "X-Forwarded-For", "2001:db8:1:2::ffff"), 429, "same /64 blocked")
	e.want(e.do("POST", url, "", map[string]any{"password": "secret12"}, "X-Forwarded-For", "2001:db8:1:3::1"), 200, "other /64 unlocks")
}
