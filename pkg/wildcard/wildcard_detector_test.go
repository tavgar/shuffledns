package wildcard

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

type fakeDNS struct {
	pool []string
	real map[string]string
	ttl  uint32
}

func (f *fakeDNS) QueryOne(host string) (*retryabledns.DNSData, error) {
	ip := f.real[host]
	if ip == "" {
		ip = f.pool[rand.Intn(len(f.pool))]
	}
	return &retryabledns.DNSData{Host: host, TTL: f.ttl, A: []string{ip}, StatusCodeRaw: dns.RcodeSuccess}, nil
}

func TestBaselineDetector(t *testing.T) {
	fake := &fakeDNS{pool: []string{"52.95.245.1", "52.95.245.2"}, real: map[string]string{"real.example.com": "1.1.1.1"}, ttl: 60}
	d, err := NewDetector(Options{Domains: []string{"example.com"}, Samples: 0, Threshold: 100, Retries: 1, Resolvers: []string{"udp:127.0.0.1:53"}})
	require.NoError(t, err)
	d.client = fake
	d.baseline["example.com"] = [][]AnswerSet{
		{{RecordType: "A", TTL: 60, Rdata: []string{"52.95.245.1"}}},
		{{RecordType: "A", TTL: 60, Rdata: []string{"52.95.245.2"}}},
	}

	r1, _ := fake.QueryOne("rand.example.com")
	require.True(t, d.ShouldFilter(r1))
	r2, _ := fake.QueryOne("real.example.com")
	require.False(t, d.ShouldFilter(r2))
}

func TestThreshold(t *testing.T) {
	pool := make([]string, 100)
	for i := range pool {
		pool[i] = fmt.Sprintf("52.95.245.%d", i)
	}
	baseline := map[string][][]AnswerSet{
		"example.com": {{
			{RecordType: "A", TTL: 60, Rdata: pool},
		}},
	}
	d := &Detector{baseline: baseline, options: Options{Domains: []string{"example.com"}, Threshold: 90}}
	d.client = &fakeDNS{pool: pool, ttl: 60}
	resp := &retryabledns.DNSData{Host: "foo.example.com", TTL: 60, A: pool}
	require.True(t, d.ShouldFilter(resp))
	resp2 := &retryabledns.DNSData{Host: "bar.example.com", TTL: 60, A: pool[:50]}
	require.False(t, d.ShouldFilter(resp2))
}

func TestPersistence(t *testing.T) {
	fake := &fakeDNS{pool: []string{"52.95.245.1"}, ttl: 60}
	d, _ := NewDetector(Options{Domains: []string{"example.com"}, Samples: 0, Retries: 1, Resolvers: []string{"udp:127.0.0.1:53"}})
	d.client = fake
	d.options.Samples = 1
	d.baseline["example.com"] = [][]AnswerSet{{{RecordType: "A", TTL: 60, Rdata: []string{"52.95.245.1"}}}}
	path := t.TempDir() + "/b.json"
	require.NoError(t, d.save(path))

	d2, err := NewDetector(Options{Domains: []string{"example.com"}, LoadPath: path, Retries: 1, Resolvers: []string{"udp:127.0.0.1:53"}})
	require.NoError(t, err)
	d2.client = fake
	resp, _ := fake.QueryOne("x.example.com")
	require.Equal(t, d.ShouldFilter(resp), d2.ShouldFilter(resp))
}
