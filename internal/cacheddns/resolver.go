package cacheddns

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

const (
	defaultCapacity    = 4096
	defaultTimeout     = 2 * time.Second
	defaultNegativeTTL = 30 * time.Second
)

var errNoAddress = errors.New("DNS response contains no address")

// NegativePolicy controls what happens when a cached negative DNS answer is found.
type NegativePolicy string

const (
	// NegativeReturn returns an unexpired cached negative answer immediately.
	NegativeReturn NegativePolicy = "return"
	// NegativeRetry keeps negative answers as fallback state, but retries upstream first.
	NegativeRetry NegativePolicy = "retry"
	// NegativeOff does not cache negative answers.
	NegativeOff NegativePolicy = "off"
)

// ParseNegativePolicy validates a CLI/config value.
func ParseNegativePolicy(raw string) (NegativePolicy, error) {
	p := NegativePolicy(strings.ToLower(strings.TrimSpace(raw)))
	switch p {
	case NegativeReturn, NegativeRetry, NegativeOff:
		return p, nil
	default:
		return "", fmt.Errorf("invalid negative cache policy %q (want return, retry, or off)", raw)
	}
}

// DialContextFunc supplies the transport used to reach DNS upstreams. For
// tunnel mode this can be L4Proxy.DialContext; for direct mode use net.Dialer.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Options configure a Resolver.
type Options struct {
	Upstreams      []netip.Addr
	DialContext    DialContextFunc
	Timeout        time.Duration
	Capacity       int
	NegativeTTL    time.Duration
	NegativePolicy NegativePolicy
}

// Resolver is a small TTL-aware caching DNS forwarder for A/AAAA lookups. It
// races all configured upstreams and returns the first usable answer.
type Resolver struct {
	upstreams      []string
	dialContext    DialContextFunc
	timeout        time.Duration
	negativeTTL    time.Duration
	negativePolicy NegativePolicy
	client         *dns.Client
	cache          *responseCache
}

// New constructs a Resolver. DNS upstreams are literal IP addresses so the
// resolver never depends on host DNS just to find its own upstreams.
func New(opts Options) (*Resolver, error) {
	if len(opts.Upstreams) == 0 {
		return nil, fmt.Errorf("no DNS upstreams configured")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Capacity <= 0 {
		opts.Capacity = defaultCapacity
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = defaultNegativeTTL
	}
	if opts.NegativePolicy == "" {
		opts.NegativePolicy = NegativeReturn
	}
	if _, err := ParseNegativePolicy(string(opts.NegativePolicy)); err != nil {
		return nil, err
	}
	if opts.DialContext == nil {
		d := &net.Dialer{}
		opts.DialContext = d.DialContext
	}

	upstreams := make([]string, 0, len(opts.Upstreams))
	for _, addr := range opts.Upstreams {
		if !addr.IsValid() {
			return nil, fmt.Errorf("invalid DNS upstream address")
		}
		upstreams = append(upstreams, net.JoinHostPort(addr.String(), "53"))
	}

	return &Resolver{
		upstreams:      upstreams,
		dialContext:    opts.DialContext,
		timeout:        opts.Timeout,
		negativeTTL:    opts.NegativeTTL,
		negativePolicy: opts.NegativePolicy,
		client:         dns.NewClient(),
		cache:          newResponseCache(opts.Capacity),
	}, nil
}

// Resolve implements api.DNSResolver. IPv4 is preferred for parity with the
// previous resolver; AAAA is tried when A has no usable address.
func (r *Resolver) Resolve(ctx context.Context, name string) (net.IP, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, &net.DNSError{Err: "empty DNS name", Name: name}
	}

	var lastErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		ip, nxDomain, err := r.resolveType(ctx, name, qtype)
		if err == nil && ip != nil {
			return ip, nil
		}
		if nxDomain {
			return nil, notFound(name)
		}
		if err != nil && !errors.Is(err, errNoAddress) {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, notFound(name)
}

func (r *Resolver) resolveType(ctx context.Context, name string, qtype uint16) (net.IP, bool, error) {
	key := cacheKey{name: strings.ToLower(strings.TrimSuffix(name, ".")), qtype: qtype}
	var cachedNegative *cacheEntry
	if entry, ok := r.cache.get(key, time.Now()); ok {
		if !entry.negative {
			if ip := selectIP(entry.msg, qtype, entry.next); ip != nil {
				return ip, false, nil
			}
		} else {
			switch r.negativePolicy {
			case NegativeReturn:
				return nil, entry.nxDomain, errNoAddress
			case NegativeRetry:
				cachedNegative = entry
			}
		}
	}

	msg, err := r.query(ctx, name, qtype)
	if err != nil {
		if cachedNegative != nil {
			return nil, cachedNegative.nxDomain, errNoAddress
		}
		return nil, false, err
	}

	nxDomain := msg.Rcode == dns.RcodeNameError
	ip := selectIP(msg, qtype, 0)
	negative := nxDomain || (msg.Rcode == dns.RcodeSuccess && ip == nil)
	if msg.Rcode != dns.RcodeSuccess && !nxDomain {
		return nil, false, fmt.Errorf("DNS lookup for %s returned %s", name, rcodeString(msg.Rcode))
	}

	if negative {
		if r.negativePolicy != NegativeOff {
			ttl := negativeResponseTTL(msg, r.negativeTTL)
			if ttl > 0 {
				r.cache.put(key, msg, time.Now().Add(ttl), true, nxDomain, 0)
			}
		}
		return nil, nxDomain, errNoAddress
	}

	ttl := responseTTL(msg)
	if ttl > 0 {
		// The first address is returned now, so start cache-hit round robin at 1.
		r.cache.put(key, msg, time.Now().Add(ttl), false, false, 1)
	}
	return ip, false, nil
}

func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	type result struct {
		msg *dns.Msg
		err error
	}

	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(r.upstreams))

	for _, upstream := range r.upstreams {
		go func(upstream string) {
			upCtx := queryCtx
			var upCancel context.CancelFunc
			if r.timeout > 0 {
				upCtx, upCancel = context.WithTimeout(queryCtx, r.timeout)
				defer upCancel()
			}
			conn, err := r.dialContext(upCtx, "tcp", upstream)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer conn.Close()

			q := dns.NewMsg(name, qtype)
			if q == nil {
				results <- result{err: fmt.Errorf("unsupported DNS query type %d", qtype)}
				return
			}
			msg, _, err := r.client.ExchangeWithConn(upCtx, q, conn)
			results <- result{msg: msg, err: err}
		}(upstream)
	}

	var lastErr error
	for range r.upstreams {
		res := <-results
		if res.err != nil {
			lastErr = res.err
			continue
		}
		if res.msg == nil {
			lastErr = fmt.Errorf("empty DNS response")
			continue
		}
		if res.msg.Rcode == dns.RcodeServerFailure {
			lastErr = fmt.Errorf("DNS upstream returned SERVFAIL")
			continue
		}
		cancel()
		return res.msg, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all DNS upstreams failed")
	}
	return nil, lastErr
}

func selectIP(msg *dns.Msg, qtype uint16, n uint64) net.IP {
	if msg == nil {
		return nil
	}
	addrs := make([]netip.Addr, 0, 4)
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA && rr.Addr.IsValid() {
				addrs = append(addrs, rr.Addr)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA && rr.Addr.IsValid() {
				addrs = append(addrs, rr.Addr)
			}
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	addr := addrs[n%uint64(len(addrs))]
	return net.IP(append([]byte(nil), addr.AsSlice()...))
}

func responseTTL(msg *dns.Msg) time.Duration {
	if msg == nil {
		return 0
	}
	var min uint32
	found := false
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			ttl := rr.Header().TTL
			if !found || ttl < min {
				min = ttl
				found = true
			}
		}
	}
	if !found || min == 0 {
		return 0
	}
	return time.Duration(min) * time.Second
}

func negativeResponseTTL(msg *dns.Msg, fallback time.Duration) time.Duration {
	if msg != nil {
		for _, rr := range msg.Ns {
			soa, ok := rr.(*dns.SOA)
			if !ok {
				continue
			}
			ttl := soa.Hdr.TTL
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			if ttl > 0 {
				return time.Duration(ttl) * time.Second
			}
		}
	}
	return fallback
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func rcodeString(rcode uint16) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	key      cacheKey
	msg      *dns.Msg
	expires  time.Time
	negative bool
	nxDomain bool
	next     uint64
}

type responseCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[cacheKey]*list.Element
	lru      *list.List
}

func newResponseCache(capacity int) *responseCache {
	return &responseCache{capacity: capacity, entries: make(map[cacheKey]*list.Element), lru: list.New()}
}

func (c *responseCache) get(key cacheKey, now time.Time) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if !now.Before(entry.expires) {
		c.remove(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	copyEntry := *entry
	if !entry.negative {
		entry.next++
	}
	return &copyEntry, true
}

func (c *responseCache) put(key cacheKey, msg *dns.Msg, expires time.Time, negative, nxDomain bool, next uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.msg = msg
		entry.expires = expires
		entry.negative = negative
		entry.nxDomain = nxDomain
		entry.next = next
		c.lru.MoveToFront(el)
		return
	}
	entry := &cacheEntry{key: key, msg: msg, expires: expires, negative: negative, nxDomain: nxDomain, next: next}
	el := c.lru.PushFront(entry)
	c.entries[key] = el
	for c.lru.Len() > c.capacity {
		c.remove(c.lru.Back())
	}
}

func (c *responseCache) remove(el *list.Element) {
	if el == nil {
		return
	}
	entry := el.Value.(*cacheEntry)
	delete(c.entries, entry.key)
	c.lru.Remove(el)
}
