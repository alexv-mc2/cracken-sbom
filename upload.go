package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const uploadLimit = 16 << 20

var uploadTokenPattern = regexp.MustCompile(`^crk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}$`)
var uploadUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var uploadCursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
var uploadIdempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)

type uploadExitError struct {
	code    int
	message string
}

func (e *uploadExitError) Error() string { return e.message }
func cliExitCode(err error) int {
	var e *uploadExitError
	if errors.As(err, &e) {
		return e.code
	}
	return 1
}
func uploadError(code int, message string) error { return &uploadExitError{code, message} }

type uploadOptions struct {
	sbom, releaseID, projectID, slug, version, label, apiURL, idempotency, failOn string
	wait, json                                                                    bool
	timeout                                                                       time.Duration
}
type uploadDeps struct {
	client   *http.Client
	getenv   func(string) string
	readFile func(string) (io.ReadCloser, error)
	sleep    func(context.Context, time.Duration) error
	now      func() time.Time
}

func uploadDialer() *net.Dialer {
	return &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
}

func uploadTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = uploadDialer().DialContext
	transport.TLSHandshakeTimeout = 15 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	return transport
}

func uploadDependencies() uploadDeps {
	return uploadDeps{client: &http.Client{Transport: uploadTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, getenv: os.Getenv, readFile: func(p string) (io.ReadCloser, error) { return os.Open(p) }, sleep: func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}, now: time.Now}
}
func parseUpload(args []string) (uploadOptions, error) {
	var o uploadOptions
	f := flag.NewFlagSet("upload", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for _, v := range []struct {
		p *string
		n string
	}{{&o.sbom, "sbom"}, {&o.releaseID, "release-id"}, {&o.projectID, "project-id"}, {&o.slug, "project-slug"}, {&o.version, "version"}, {&o.label, "release-label"}, {&o.apiURL, "api-url"}, {&o.idempotency, "idempotency-key"}, {&o.failOn, "fail-on"}} {
		f.StringVar(v.p, v.n, "", "")
	}
	f.BoolVar(&o.wait, "wait", false, "")
	f.BoolVar(&o.json, "json", false, "")
	f.DurationVar(&o.timeout, "timeout", 15*time.Minute, "")
	if f.Parse(args) != nil || f.NArg() != 0 || o.sbom == "" || o.timeout <= 0 {
		return o, uploadError(1, uploadUsage)
	}
	n := 0
	for _, v := range []string{o.releaseID, o.projectID, o.slug} {
		if v != "" {
			n++
		}
	}
	o.version = strings.TrimSpace(o.version)
	if n != 1 || (o.releaseID != "" && (o.version != "" || !uploadUUIDPattern.MatchString(o.releaseID))) || (o.releaseID == "" && (len(o.version) < 1 || len(o.version) > 100)) || (o.projectID != "" && !uploadUUIDPattern.MatchString(o.projectID)) || len(o.label) > 200 || (o.idempotency != "" && !uploadIdempotencyPattern.MatchString(o.idempotency)) {
		return o, uploadError(1, uploadUsage)
	}
	if o.failOn != "" {
		switch o.failOn {
		case "critical", "high", "medium", "low":
			o.wait = true
		default:
			return o, uploadError(1, uploadUsage)
		}
	}
	return o, nil
}
func uploadBase(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (strings.Contains(raw, "crk_") || strings.Contains(u.Path, "crk_")) {
		return nil, uploadError(1, uploadURL)
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, uploadError(1, uploadURL)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}
func readUpload(o uploadOptions, d uploadDeps) ([]byte, string, error) {
	f, e := d.readFile(o.sbom)
	if e != nil {
		return nil, "", uploadError(1, uploadFile)
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, uploadLimit+1))
	if e != nil || len(b) > uploadLimit || bytes.HasPrefix(b, []byte("PK")) {
		return nil, "", uploadError(1, uploadFile)
	}
	var doc map[string]json.RawMessage
	clean := bytes.TrimPrefix(b, []byte{239, 187, 191})
	if json.Unmarshal(clean, &doc) != nil || doc == nil {
		return nil, "", uploadError(1, uploadFormat)
	}
	var v string
	json.Unmarshal(doc["bomFormat"], &v)
	if v == "CycloneDX" {
		return b, "application/vnd.cyclonedx+json", nil
	}
	json.Unmarshal(doc["spdxVersion"], &v)
	if regexp.MustCompile(`^SPDX-2\.[0-9]+$`).MatchString(v) {
		return b, "application/spdx+json", nil
	}
	if bytes.Contains(doc["@context"], []byte("spdx.org/rdf/3")) {
		return b, "application/spdx+json", nil
	}
	return nil, "", uploadError(1, uploadFormat)
}
func uploadTarget(o uploadOptions) url.Values {
	q := url.Values{}
	if o.releaseID != "" {
		q.Set("release_id", strings.ToLower(o.releaseID))
	} else {
		if o.projectID != "" {
			q.Set("project_id", strings.ToLower(o.projectID))
		} else {
			q.Set("project_slug", o.slug)
		}
		q.Set("version", o.version)
	}
	if o.label != "" {
		q.Set("release_label", o.label)
	}
	return q
}
func uploadIdempotency(o uploadOptions, b []byte) string {
	if o.idempotency != "" {
		return o.idempotency
	}
	h := sha256.Sum256(b)
	q := uploadTarget(o)
	q.Del("version")
	s := sha256.Sum256([]byte(hex.EncodeToString(h[:]) + "\n" + q.Encode() + "\n" + o.version))
	return "cs1-" + hex.EncodeToString(s[:])[:48]
}
func uploadAddress(base *url.URL, path string, q url.Values) string {
	u := *base
	u.Path += path
	u.RawQuery = q.Encode()
	return u.String()
}
func retryDelay(h string, now time.Time) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	seconds, err := strconv.ParseUint(h, 10, 64)
	if err == nil {
		if seconds > uint64(maximum/time.Second) {
			return maximum
		}
		return time.Duration(seconds) * time.Second
	}
	if errors.Is(err, strconv.ErrRange) {
		return maximum
	}
	if t, e := http.ParseTime(h); e == nil && t.After(now) {
		return t.Sub(now)
	}
	return time.Second
}

func uploadRequest(ctx context.Context, d uploadDeps, key, method, address, media, idem string, b []byte) ([]byte, error) {
	// Copy the client to enforce redirect refusal even with injected transports.
	c := *d.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; ; attempt++ {
		r, e := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(b))
		if e != nil {
			return nil, uploadError(1, uploadNetwork)
		}
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Cracken-Client", "cracken-sbom/"+toolVersion)
		if media != "" {
			r.Header.Set("Content-Type", media)
		}
		if idem != "" {
			r.Header.Set("Idempotency-Key", idem)
		}
		resp, e := c.Do(r)
		delay := time.Duration(2<<attempt) * time.Second
		if e != nil {
			if ctx.Err() != nil {
				return nil, uploadError(4, uploadTimeout)
			}
			if attempt >= 3 {
				return nil, uploadError(1, uploadNetwork)
			}
		} else {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if ctx.Err() != nil {
					return nil, uploadError(4, uploadTimeout)
				}
				if readErr != nil {
					var networkError net.Error
					if !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.As(readErr, &networkError) {
						return nil, uploadError(1, uploadInvalid)
					}
					if attempt >= 3 {
						return nil, uploadError(1, uploadNetwork)
					}
					if d.sleep(ctx, delay) != nil {
						return nil, uploadError(4, uploadTimeout)
					}
					continue
				}
				if len(data) > 1<<20 {
					return nil, uploadError(1, uploadInvalid)
				}
				return data, nil
			}
			if resp.StatusCode == 403 {
				var payload struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				json.Unmarshal(data, &payload)
				if payload.Error.Code == "insufficient_scope" && strings.Contains(address, "/v1/findings?") {
					return nil, uploadError(1, uploadScope)
				}
			}
			if attempt >= 3 || (resp.StatusCode != 429 && resp.StatusCode < 500) {
				return nil, uploadError(1, fmt.Sprintf(uploadHTTP, resp.StatusCode))
			}
			if resp.StatusCode == 429 {
				delay = retryDelay(resp.Header.Get("Retry-After"), d.now())
			}
		}
		if d.sleep(ctx, delay) != nil {
			return nil, uploadError(4, uploadTimeout)
		}
	}
}
func runUpload(ctx context.Context, args []string, out io.Writer, d uploadDeps) (err error) {
	result := struct {
		AnalysisID string `json:"analysis_id,omitempty"`
		Status     string `json:"status"`
		ExitCode   int    `json:"exit_code"`
	}{Status: "error"}
	o, err := parseUpload(args)
	jsonOutput := o.json
	if jsonOutput {
		defer func() {
			result.ExitCode = cliExitCode(err)
			if err == nil {
				result.ExitCode = 0
			}
			if e := json.NewEncoder(out).Encode(result); err == nil && e != nil {
				err = uploadError(1, uploadInvalid)
			}
		}()
	}
	if err != nil {
		return err
	}
	key := d.getenv("CRACKEN_API_KEY")
	if !uploadTokenPattern.MatchString(key) {
		return uploadError(1, uploadKey)
	}
	for _, v := range []string{o.slug, o.version, o.label, o.idempotency} {
		if strings.Contains(v, key) || strings.Contains(v, "crk_") {
			return uploadError(1, uploadUsage)
		}
	}
	if o.apiURL == "" {
		o.apiURL = d.getenv("CRACKEN_API_URL")
	}
	base, err := uploadBase(o.apiURL)
	if err != nil {
		return err
	}
	emit := func(message string) {
		if !jsonOutput {
			fmt.Fprintln(out, message)
		}
	}
	b, media, err := readUpload(o, d)
	if err != nil {
		return err
	}
	uploadCtx, cancelUpload := context.WithTimeout(ctx, o.timeout)
	data, err := uploadRequest(uploadCtx, d, key, "POST", uploadAddress(base, "/v1/sboms", uploadTarget(o)), media, uploadIdempotency(o, b), b)
	cancelUpload()
	if err != nil {
		return err
	}
	var accepted struct {
		AnalysisID string `json:"analysis_id"`
	}
	if json.Unmarshal(data, &accepted) != nil || !uploadUUIDPattern.MatchString(accepted.AnalysisID) {
		return uploadError(1, uploadInvalid)
	}
	result.AnalysisID = accepted.AnalysisID
	result.Status = "queued"
	emit(fmt.Sprintf(uploadAccepted, accepted.AnalysisID))
	if !o.wait {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	for {
		data, err = uploadRequest(waitCtx, d, key, "GET", uploadAddress(base, "/v1/analyses/"+accepted.AnalysisID, nil), "", "", nil)
		if err != nil {
			return err
		}
		var state struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(data, &state) != nil {
			return uploadError(1, uploadInvalid)
		}
		if state.Status == "failed" {
			result.Status = state.Status
			emit(uploadFailed)
			return uploadError(2, uploadFailed)
		}
		if state.Status == "succeeded" {
			result.Status = state.Status
			emit(uploadSucceeded)
			break
		}
		switch state.Status {
		case "queued", "running":
		default:
			return uploadError(1, uploadInvalid)
		}
		if d.sleep(waitCtx, 5*time.Second) != nil {
			return uploadError(4, uploadTimeout)
		}
	}
	if o.failOn == "" {
		return nil
	}
	q := url.Values{"analysis_id": {accepted.AnalysisID}, "min_severity": {o.failOn}}
	found := false
	seen := map[string]bool{}
	for {
		data, err = uploadRequest(waitCtx, d, key, "GET", uploadAddress(base, "/v1/findings", q), "", "", nil)
		if err != nil {
			return err
		}
		var page struct {
			Data []json.RawMessage `json:"data"`
			Next *string           `json:"next_cursor"`
		}
		var keys map[string]json.RawMessage
		if json.Unmarshal(data, &keys) != nil || keys["data"] == nil || keys["next_cursor"] == nil || json.Unmarshal(data, &page) != nil || page.Data == nil {
			return uploadError(1, uploadInvalid)
		}
		found = found || len(page.Data) > 0
		if page.Next == nil {
			break
		}
		if !uploadCursorPattern.MatchString(*page.Next) || seen[*page.Next] || strings.Contains(*page.Next, key) || strings.Contains(*page.Next, "crk_") {
			return uploadError(1, uploadInvalid)
		}
		seen[*page.Next] = true
		q.Set("cursor", *page.Next)
	}
	if found {
		emit(uploadFindings)
		return uploadError(3, uploadFindings)
	}
	emit(uploadNoFindings)
	return nil
}
