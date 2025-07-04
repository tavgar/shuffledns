package wildcard

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	"github.com/rs/xid"
)

// Options contains configuration for the baseline detector.
type Options struct {
	Domains   []string
	Resolvers []string
	Retries   int
	Samples   int
	Threshold int
	SavePath  string
	LoadPath  string
	Log       bool
	Silent    bool
}

// Detector checks results against a baseline of wildcard answers.
type queryClient interface {
	QueryOne(string) (*retryabledns.DNSData, error)
}

type Detector struct {
	client   queryClient
	options  Options
	baseline map[string][][]AnswerSet // domain -> list of baselines
	lock     sync.RWMutex
}

// NewDetector creates a baseline detector.
// It returns a predicate that returns true when a DNS response
// matches the baseline (ie should be treated as wildcard).
func NewDetector(opts Options) (*Detector, error) {
	d := &Detector{
		options:  opts,
		baseline: make(map[string][][]AnswerSet),
	}

	dnsOpts := dnsx.DefaultOptions
	dnsOpts.BaseResolvers = opts.Resolvers
	dnsOpts.MaxRetries = opts.Retries
	client, err := dnsx.New(dnsOpts)
	if err != nil {
		return nil, fmt.Errorf("dns client: %w", err)
	}
	d.client = client

	if opts.LoadPath != "" {
		if err := d.load(opts.LoadPath); err != nil {
			return nil, err
		}
		return d, nil
	}

	if err := d.sample(); err != nil {
		return nil, err
	}

	if opts.SavePath != "" {
		if err := d.save(opts.SavePath); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *Detector) logf(format string, v ...interface{}) {
	if d.options.Log && !d.options.Silent {
		gologger.Info().Msgf(format, v...)
	}
}

// sample builds baseline data for each root domain serially.
func (d *Detector) sample() error {
	for _, domain := range d.options.Domains {
		for i := 0; i < d.options.Samples; i++ {
			host := xid.New().String() + "." + domain
			resp, err := d.client.QueryOne(host)
			if err != nil || resp == nil || resp.StatusCodeRaw != dns.RcodeSuccess {
				continue
			}
			set := buildAnswerSet(resp)
			d.lock.Lock()
			d.baseline[domain] = append(d.baseline[domain], set)
			d.lock.Unlock()
		}
	}
	return nil
}

func buildAnswerSet(resp *retryabledns.DNSData) []AnswerSet {
	var set []AnswerSet
	if len(resp.A) > 0 {
		set = append(set, AnswerSet{RecordType: "A", TTL: resp.TTL, Rdata: append([]string(nil), resp.A...)})
	}
	if len(resp.AAAA) > 0 {
		set = append(set, AnswerSet{RecordType: "AAAA", TTL: resp.TTL, Rdata: append([]string(nil), resp.AAAA...)})
	}
	if len(resp.CNAME) > 0 {
		set = append(set, AnswerSet{RecordType: "CNAME", TTL: resp.TTL, Rdata: append([]string(nil), resp.CNAME...)})
	}
	if len(resp.NS) > 0 {
		set = append(set, AnswerSet{RecordType: "NS", TTL: resp.TTL, Rdata: append([]string(nil), resp.NS...)})
	}
	if len(resp.MX) > 0 {
		set = append(set, AnswerSet{RecordType: "MX", TTL: resp.TTL, Rdata: append([]string(nil), resp.MX...)})
	}
	if len(resp.TXT) > 0 {
		set = append(set, AnswerSet{RecordType: "TXT", TTL: resp.TTL, Rdata: append([]string(nil), resp.TXT...)})
	}
	if len(resp.SRV) > 0 {
		set = append(set, AnswerSet{RecordType: "SRV", TTL: resp.TTL, Rdata: append([]string(nil), resp.SRV...)})
	}
	if len(resp.CAA) > 0 {
		set = append(set, AnswerSet{RecordType: "CAA", TTL: resp.TTL, Rdata: append([]string(nil), resp.CAA...)})
	}
	return set
}

// ShouldFilter returns true if the provided response should be treated as wildcard.
func (d *Detector) ShouldFilter(resp *retryabledns.DNSData) bool {
	if resp == nil {
		return false
	}
	domain := ""
	host := dns.CanonicalName(resp.Host)
	for _, dname := range d.options.Domains {
		if dns.IsSubDomain(dns.Fqdn(dname), host) {
			domain = dname
			break
		}
	}
	if domain == "" {
		return false
	}

	set := buildAnswerSet(resp)
	hash := HashSet(set)

	d.lock.RLock()
	baselines := d.baseline[domain]
	d.lock.RUnlock()

	for _, b := range baselines {
		if hash == HashSet(b) {
			d.logf("wildcard match for %s", resp.Host)
			return true
		}
		if d.options.Threshold < 100 {
			if overlapPercent(b, set) >= d.options.Threshold {
				d.logf("wildcard threshold match for %s", resp.Host)
				return true
			}
		}
	}
	return false
}

func overlapPercent(a, b []AnswerSet) int {
	amap := make(map[string]struct{})
	for _, ans := range a {
		for _, r := range ans.Rdata {
			amap[ans.RecordType+":"+r] = struct{}{}
		}
	}
	total := len(amap)
	if total == 0 {
		return 0
	}
	var count int
	for _, ans := range b {
		for _, r := range ans.Rdata {
			if _, ok := amap[ans.RecordType+":"+r]; ok {
				count++
			}
		}
	}
	return int(float64(count) / float64(total) * 100)
}

func (d *Detector) save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	d.lock.RLock()
	defer d.lock.RUnlock()
	return enc.Encode(d.baseline)
}

func (d *Detector) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	return dec.Decode(&d.baseline)
}

// PredicateFunc is a helper to return as predicate function.
func (d *Detector) Predicate() func(*retryabledns.DNSData) bool {
	return d.ShouldFilter
}
