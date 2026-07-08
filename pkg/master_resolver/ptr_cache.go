package masterresolver

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// ptrCacheTTL bounds how long a reverse-DNS result is reused; pod IPs get
// recycled, so a cached name must not outlive its owner for long.
const ptrCacheTTL = time.Minute

// ptrCache caches reverse-DNS lookups of node IPs for log messages.
type ptrCache struct {
	lock    sync.Mutex
	entries map[string]ptrEntry // ip -> reverse-DNS name ("" = none)
}

type ptrEntry struct {
	name string
	when time.Time
}

func newPTRCache() *ptrCache {
	return &ptrCache{entries: map[string]ptrEntry{}}
}

// Lookup returns a cached reverse-DNS name for ip, or "" if it has none.
func (c *ptrCache) Lookup(ctx context.Context, ip string) string {
	c.lock.Lock()
	defer c.lock.Unlock()
	if e, ok := c.entries[ip]; ok && time.Since(e.when) < ptrCacheTTL {
		return e.name
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var name string
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil {
		name = pickPTRName(ip, names)
	}
	c.entries[ip] = ptrEntry{name: name, when: time.Now()} // negatives too
	return name
}

// pickPTRName prefers a record that isn't just the IP re-encoded (Kubernetes
// also publishes 10-42-4-18.<service>... names next to the pod name).
func pickPTRName(ip string, names []string) string {
	dashed := strings.NewReplacer(".", "-", ":", "-").Replace(ip) + "."
	var best string
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if best == "" {
			best = name
		}
		if !strings.HasPrefix(name, dashed) {
			return name
		}
	}
	return best
}
