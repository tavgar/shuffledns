package runner

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	retryabledns "github.com/projectdiscovery/retryabledns"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/rs/xid"
	"github.com/tavgar/shuffledns/pkg/massdns"
	"github.com/tavgar/shuffledns/pkg/wildcard"
	wildcards "github.com/tavgar/shuffledns/pkg/wildcards"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	tempDir string
	options *Options
}

// Prepare initializes helpers needed before running enumeration.
func (r *Runner) Prepare() error {
	resolvers, _ := wildcards.LoadResolversFromFile(r.options.ResolversFile)
	detector, err := wildcard.NewDetector(wildcard.Options{
		Domains:   r.options.Domains,
		Resolvers: resolvers,
		Retries:   r.options.Retries,
		Samples:   r.options.WildcardBaseline,
		Threshold: r.options.WildcardThreshold,
		SavePath:  r.options.WildcardSave,
		LoadPath:  r.options.WildcardLoad,
		Log:       r.options.WildcardLog,
		Silent:    r.options.Silent,
	})
	if err != nil {
		return err
	}

	prev := r.options.OnResult
	r.options.OnResult = func(d *retryabledns.DNSData) {
		if detector.ShouldFilter(d) {
			return
		}
		if prev != nil {
			prev(d)
		}
	}
	return nil
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}

	// Setup the massdns binary path if none was give.
	// If no valid path found, return an error
	if options.MassdnsPath == "" {
		options.MassdnsPath = runner.findBinary()
		if options.MassdnsPath == "" {
			return nil, errors.New("could not find massdns binary")
		}
		gologger.Debug().Msgf("Discovered massdns binary at %s\n", options.MassdnsPath)
	}

	// Create a temporary directory that will be removed at the end
	// of enumeration process.
	dir, err := os.MkdirTemp(options.Directory, "shuffledns-*")
	if err != nil {
		return nil, err
	}
	runner.tempDir = dir

	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	_ = os.RemoveAll(r.tempDir)
}

// findBinary searches for massdns binary in various pre-defined paths
// only linux and macos paths are supported rn
func (r *Runner) findBinary() string {
	otherCommonLocations := []string{
		"/usr/bin/massdns",
		"/usr/local/bin/massdns",
		"/data/data/com.termux/files/usr/bin/massdns",
	}

	for _, file := range otherCommonLocations {
		if fileutil.FileExists(file) {
			return file
		}
	}

	file, err := exec.LookPath("massdns")
	if err != nil {
		return ""
	}

	return file
}

// RunEnumeration sets up the input layer for giving input to massdns
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	if err := r.Prepare(); err != nil {
		gologger.Error().Msgf("preparing runner: %s", err)
		return
	}
	// Handle only wildcard filtering
	if r.options.MassdnsRaw != "" {
		r.processSubdomains()
		return
	}

	// Handle a domain to bruteforce with wordlist
	if r.options.Wordlist != "" {
		r.processDomain()
		return
	}

	// Handle a list of subdomains to resolve
	if r.options.SubdomainsList != "" || fileutil.HasStdin() {
		r.processSubdomains()
		return
	}
}

// processDomain processes the bruteforce for a domain using a wordlist
func (r *Runner) processDomain() {
	resolveFile := filepath.Join(r.tempDir, xid.New().String())
	file, err := os.Create(resolveFile)
	if err != nil {
		gologger.Error().Msgf("Could not create bruteforce list (%s): %s\n", r.tempDir, err)
		return
	}
	writer := bufio.NewWriter(file)

	// Read the input wordlist for bruteforce generation
	inputFile, err := os.Open(r.options.Wordlist)
	if err != nil {
		gologger.Error().Msgf("Could not read bruteforce wordlist (%s): %s\n", r.options.Wordlist, err)
		_ = file.Close()
		return
	}

	gologger.Info().Msgf("Started generating bruteforce permutation\n")

	now := time.Now()
	// Create permutation for domain with wordlist
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		// RFC4343 - case insensitive domain
		text := strings.ToLower(scanner.Text())
		if text == "" {
			continue
		}
		for _, domain := range r.options.Domains {
			_, _ = writer.WriteString(text + "." + domain + "\n")
		}
	}
	_ = writer.Flush()
	_ = inputFile.Close()
	_ = file.Close()

	gologger.Info().Msgf("Generating permutations took %s at %s\n", time.Since(now), resolveFile)

	// Run the actual massdns enumeration process
	r.runMassdns(resolveFile)
}

// processSubdomain processes the resolving for a list of subdomains
func (r *Runner) processSubdomains() {
	var resolveFile string

	// If there is stdin, write the resolution list to the file
	if fileutil.HasStdin() && r.options.SubdomainsList == "" {
		file, err := os.CreateTemp(r.tempDir, "massdns-stdin-")
		if err != nil {
			gologger.Error().Msgf("Could not create resolution list (%s): %s\n", r.tempDir, err)
			return
		}
		_, _ = io.Copy(file, os.Stdin)
		_ = file.Close()
		resolveFile = file.Name()
	} else {
		// Use the file if user has provided one
		resolveFile = r.options.SubdomainsList
	}

	// Run the actual massdns enumeration process
	r.runMassdns(resolveFile)
}

// runMassdns runs the massdns tool on the list of inputs
func (r *Runner) runMassdns(inputFile string) {
	massdns, err := massdns.New(massdns.Options{
		Domains:            r.options.Domains,
		Retries:            r.options.Retries,
		MassdnsPath:        r.options.MassdnsPath,
		Threads:            r.options.Threads,
		WildcardsThreads:   r.options.WildcardThreads,
		InputFile:          inputFile,
		ResolversFile:      r.options.ResolversFile,
		TrustedResolvers:   r.options.TrustedResolvers,
		TempDir:            r.tempDir,
		OutputFile:         r.options.Output,
		Json:               r.options.Json,
		MassdnsRaw:         r.options.MassdnsRaw,
		StrictWildcard:     r.options.StrictWildcard,
		WildcardOutputFile: r.options.WildcardOutputFile,
		MassDnsCmd:         r.options.MassDnsCmd,
		OnResult:           r.options.OnResult,
	})
	if err != nil {
		gologger.Error().Msgf("Could not create massdns client: %s\n", err)
		return
	}

	err = massdns.Run(context.Background())
	if err != nil {
		gologger.Error().Msgf("Could not run massdns: %s\n", err)
	}

	if r.options.WildcardOutputFile != "" {
		_ = massdns.DumpWildcardsToFile(r.options.WildcardOutputFile)
	}

	gologger.Info().Msgf("Finished resolving.\n")
}
