// Package binaryedge logic
package binaryedge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type binaryedgeResponse struct {
	Events []string `json:"events"`
	Total  int      `json:"total"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0
	s.skipped = false

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}
		domain = strings.ToLower(domain)

		for page := 1; ; page++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			s.requests++
			resp, err := session.Get(ctx, fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d", domain, page), "", map[string]string{
				"X-Key":  randomApiKey,
				"accept": "application/json",
			})
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("binaryedge page %d request failed: %w", page, err)}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}
			if resp.StatusCode != 200 {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("binaryedge page %d request failed with status %d", page, resp.StatusCode)}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var response binaryedgeResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}
			session.DiscardHTTPResponse(resp)

			if len(response.Events) == 0 {
				return
			}

			for _, item := range response.Events {
				subdomain := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(item), "."))
				if subdomain == "" {
					continue
				}
				if !strings.HasSuffix(subdomain, "."+domain) && subdomain != domain {
					if !strings.Contains(subdomain, ".") {
						subdomain = subdomain + "." + domain
					} else {
						continue
					}
				}
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results++
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "binaryedge"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Requests:  s.requests,
		Skipped:   s.skipped,
	}
}
