// SPDX-License-Identifier: AGPL-3.0-or-later

package conformance

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/adapters/inproc"
	"github.com/sendora-app/sendora/internal/adapters/postgres"
	"github.com/sendora-app/sendora/internal/ports"
)

// RuntimeBackend is one implementation of the coordination ports (Lock,
// RateLimiter, Coordinator). The pair constructors return two instances that
// share state the way two replicas do (the in-process backend returns the
// same instance twice: it has one replica by definition).
type RuntimeBackend struct {
	Name        string
	Unavailable func() string
	Lock        func(testing.TB) (ports.Lock, ports.Lock)
	Limiter     func(testing.TB, func() time.Time) (ports.RateLimiter, ports.RateLimiter)
	Coordinator func(testing.TB) (ports.Coordinator, ports.Coordinator)
}

// RuntimeBackends lists the coordination adapters the suite runs against.
func RuntimeBackends() []RuntimeBackend {
	return []RuntimeBackend{
		{
			Name:        "inproc",
			Unavailable: func() string { return "" },
			Lock: func(testing.TB) (ports.Lock, ports.Lock) {
				l := inproc.NewLock()
				return l, l
			},
			Limiter: func(_ testing.TB, now func() time.Time) (ports.RateLimiter, ports.RateLimiter) {
				r := inproc.NewRateLimiter(now)
				return r, r
			},
			Coordinator: func(testing.TB) (ports.Coordinator, ports.Coordinator) {
				c := inproc.NewCoordinator()
				return c, c
			},
		},
		{
			Name:        "postgres",
			Unavailable: postgresUnavailable,
			Lock: func(t testing.TB) (ports.Lock, ports.Lock) {
				sc := openScratch(t, postgres.PlatformSchema)
				return postgres.NewLock(sc.DB, "replica-a", 5*time.Second), postgres.NewLock(sc.DB, "replica-b", 5*time.Second)
			},
			Limiter: func(t testing.TB, now func() time.Time) (ports.RateLimiter, ports.RateLimiter) {
				sc := openScratch(t, postgres.PlatformSchema)
				key := []byte("conformance rate-limit key 32 b!")
				return postgres.NewRateLimiter(sc.DB, key, now), postgres.NewRateLimiter(sc.DB, key, now)
			},
			Coordinator: func(t testing.TB) (ports.Coordinator, ports.Coordinator) {
				sc := openScratch(t, postgres.PlatformSchema)
				listen, err := pgx.ParseConfig(os.Getenv(PGDSNEnv))
				if err != nil {
					t.Fatal(err)
				}
				mk := func(lead bool, l *pgx.ConnConfig) ports.Coordinator {
					c, err := postgres.NewCoordinator(context.Background(), postgres.CoordinatorConfig{DB: sc.DB, Listen: l,
						Elector: postgres.StaticElector{Lead: lead, Epoch: 1}, PollInterval: 200 * time.Millisecond, Logf: t.Logf})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(c.Close)
					return c
				}
				// Member A leads and listens; member B follows and only polls,
				// so both delivery paths are exercised.
				return mk(true, listen), mk(false, nil)
			},
		},
	}
}
