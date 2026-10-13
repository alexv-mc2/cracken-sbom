package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testUploadKey = "crk_" + strings.Repeat("a", 12) + "_" + strings.Repeat("A", 43)

const testAnalysisID = "11111111-1111-4111-8111-111111111111"
const testProjectID = "22222222-2222-4222-8222-222222222222"

type uploadRoundTrip func(*http.Request) (*http.Response, error)

func (f uploadRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func uploadTestDeps(f uploadRoundTrip) uploadDeps {
	return uploadDeps{client: &http.Client{Transport: f}, getenv: func(k string) string {
		if k == "CRACKEN_API_KEY" {
			return testUploadKey
		}
		return "https://api.example.test"
	}, readFile: func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)), nil
	}, sleep: func(context.Context, time.Duration) error { return nil }, now: time.Now}
}
func uploadResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func uploadArgs(extra ...string) []string {
	return append([]string{"--sbom", "named.json", "--project-id", testProjectID, "--version", "1.0"}, extra...)
}
func assertUploadCode(t *testing.T, err error, want int) {
	t.Helper()
	got := 0
	if err != nil {
		got = cliExitCode(err)
	}
	if got != want {
		t.Fatalf("code=%d want=%d error=%v", got, want, err)
	}
}
func assertUploadSafe(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil {
		out += err.Error()
	}
	for _, secret := range []string{testUploadKey, "SECRET_RESPONSE", "api.example.test/v1"} {
		if strings.Contains(out, secret) {
			t.Fatalf("unsafe output")
		}
	}
}
func TestUploadFlags(t *testing.T) {
	cases := [][]string{{}, {"--sbom", "x"}, {"--sbom", "x", "--release-id", testAnalysisID, "--version", "x"}, {"--sbom", "x", "--project-id", testProjectID}, {"--sbom", "x", "--project-id", testProjectID, "--project-slug", "x", "--version", "x"}, uploadArgs("--api-key", testUploadKey), uploadArgs("--fail-on", "none"), uploadArgs("--timeout", "0"), uploadArgs("--idempotency-key", "bad value"), uploadArgs("--release-label", strings.Repeat("x", 201)), uploadArgs("--extra", testUploadKey), uploadArgs("positional")}
	for _, args := range cases {
		_, err := parseUpload(args)
		assertUploadCode(t, err, 1)
		assertUploadSafe(t, "", err)
	}
	for _, args := range [][]string{uploadArgs(), uploadArgs("--release-label", "Build"), uploadArgs("--wait", "--timeout", "1m", "--json", "--idempotency-key", "build:1"), {"--sbom", "x", "--release-id", testAnalysisID}, {"--sbom", "x", "--project-slug", "widget", "--version", "1"}} {
		if _, err := parseUpload(args); err != nil {
			t.Fatal(err)
		}
	}
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		o, err := parseUpload(uploadArgs("--fail-on", severity))
		if err != nil || !o.wait {
			t.Fatal("fail-on must imply wait")
		}
	}
}
func TestUploadURLSafety(t *testing.T) {
	for _, raw := range []string{"https://api.example.test/functions/v1/api-v1", "http://localhost:1234", "http://127.0.0.1:1234", "http://[::1]:1234"} {
		if _, e := uploadBase(raw); e != nil {
			t.Fatal(e)
		}
	}
	for _, raw := range []string{"", "http://example.test", "https://user:password@api.example.test", "https://api.example.test?key=" + testUploadKey, "https://api.example.test#secret", "https://api.example.test?", "ftp://localhost", "https://api.example.test/path/" + testUploadKey} {
		_, e := uploadBase(raw)
		assertUploadCode(t, e, 1)
		assertUploadSafe(t, "", e)
	}
}
func TestUploadKeyEnvironmentOnly(t *testing.T) {
	for _, key := range []string{"", "bad", "Bearer " + testUploadKey} {
		d := uploadTestDeps(nil)
		d.getenv = func(string) string { return key }
		var out bytes.Buffer
		e := runUpload(context.Background(), uploadArgs(), &out, d)
		assertUploadCode(t, e, 1)
		assertUploadSafe(t, out.String(), e)
	}
}
func TestUploadFormatsAndFileLimit(t *testing.T) {
	for _, tc := range []struct {
		body, media string
		code        int
	}{{`{"bomFormat":"CycloneDX"}`, "application/vnd.cyclonedx+json", 0}, {`{"spdxVersion":"SPDX-2.3"}`, "application/spdx+json", 0}, {`{"@context":["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}`, "application/spdx+json", 0}, {"\xef\xbb\xbf{\"bomFormat\":\"CycloneDX\"}", "application/vnd.cyclonedx+json", 0}, {`[]`, "", 1}, {`{`, "", 1}, {`{"secret":"SECRET_RESPONSE"}`, "", 1}, {"PK\x03\x04zip", "", 1}, {strings.Repeat("x", uploadLimit+1), "", 1}} {
		d := uploadTestDeps(nil)
		calls := 0
		d.readFile = func(string) (io.ReadCloser, error) { calls++; return io.NopCloser(strings.NewReader(tc.body)), nil }
		_, media, e := readUpload(uploadOptions{sbom: "x"}, d)
		assertUploadCode(t, e, tc.code)
		if media != tc.media || calls != 1 {
			t.Fatalf("media=%s reads=%d", media, calls)
		}
		assertUploadSafe(t, "", e)
	}
	d := uploadTestDeps(nil)
	d.readFile = func(string) (io.ReadCloser, error) { return nil, errors.New(testUploadKey) }
	_, _, e := readUpload(uploadOptions{}, d)
	assertUploadCode(t, e, 1)
	assertUploadSafe(t, "", e)
}
func TestUploadStableIdempotency(t *testing.T) {
	o, _ := parseUpload(uploadArgs())
	b := []byte("content")
	got := uploadIdempotency(o, b)
	h := sha256.Sum256(b)
	target := "project_id=" + testProjectID
	s := sha256.Sum256([]byte(hex.EncodeToString(h[:]) + "\n" + target + "\n1.0"))
	want := "cs1-" + hex.EncodeToString(s[:])[:48]
	if got != want {
		t.Fatal("idempotency hash mismatch")
	}
	o.version = "2"
	if got == uploadIdempotency(o, b) {
		t.Fatal("version must change key")
	}
	o.idempotency = "explicit"
	if uploadIdempotency(o, b) != "explicit" {
		t.Fatal("explicit key ignored")
	}
}
func TestUploadRetriesAndHeaders(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			var idem string
			var bodies []string
			var delays []time.Duration
			d := uploadTestDeps(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "Bearer "+testUploadKey || r.Header.Get("Content-Type") != "application/vnd.cyclonedx+json" || r.Header.Get("X-Cracken-Client") != "cracken-sbom/"+toolVersion {
					t.Fatal("missing header")
				}
				k := r.Header.Get("Idempotency-Key")
				if calls == 1 {
					idem = k
				} else if k != idem {
					t.Fatal("changed idempotency key")
				}
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(b))
				if calls < 4 {
					p := uploadResponse(status, `{"error":"SECRET_RESPONSE"}`)
					p.Header.Set("Retry-After", "7")
					return p, nil
				}
				return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
			})
			d.sleep = func(_ context.Context, x time.Duration) error { delays = append(delays, x); return nil }
			var out bytes.Buffer
			e := runUpload(context.Background(), uploadArgs(), &out, d)
			assertUploadCode(t, e, 0)
			if calls != 4 {
				t.Fatal(calls)
			}
			for _, b := range bodies {
				if b != bodies[0] {
					t.Fatal("changed body")
				}
			}
			want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
			if status == 429 {
				want = []time.Duration{7 * time.Second, 7 * time.Second, 7 * time.Second}
			}
			for i, x := range want {
				if delays[i] != x {
					t.Fatal(delays)
				}
			}
			assertUploadSafe(t, out.String(), e)
		})
	}
}
func TestUploadNetworkRetriesAndHTTPFailures(t *testing.T) {
	for _, status := range []int{0, 301, 302, 307, 308, 400, 401, 403, 404, 422, 429, 500} {
		calls := 0
		d := uploadTestDeps(func(*http.Request) (*http.Response, error) {
			calls++
			if status == 0 {
				return nil, errors.New(testUploadKey)
			}
			return uploadResponse(status, `{"error":"SECRET_RESPONSE"}`), nil
		})
		var out bytes.Buffer
		e := runUpload(context.Background(), uploadArgs("--json"), &out, d)
		assertUploadCode(t, e, 1)
		want := 1
		if status == 0 || status == 429 || status == 500 {
			want = 4
		}
		if calls != want {
			t.Fatalf("status=%d calls=%d", status, calls)
		}
		assertUploadSafe(t, out.String(), e)
		var result map[string]any
		if json.Unmarshal(out.Bytes(), &result) != nil {
			t.Fatal("not one JSON result")
		}
	}
}
func TestUploadWaitAndFindingsAllPages(t *testing.T) {
	calls := 0
	d := uploadTestDeps(func(r *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
		case 2:
			return uploadResponse(200, `{"status":"queued"}`), nil
		case 3:
			return uploadResponse(200, `{"status":"succeeded"}`), nil
		case 4:
			if r.URL.Query().Get("min_severity") != "high" {
				t.Fatal("threshold missing")
			}
			return uploadResponse(200, `{"data":[],"next_cursor":"page-2"}`), nil
		case 5:
			if r.URL.Query().Get("cursor") != "page-2" {
				t.Fatal("cursor missing")
			}
			return uploadResponse(200, `{"data":[{}],"next_cursor":"page-3"}`), nil
		case 6:
			return uploadResponse(200, `{"data":[],"next_cursor":null}`), nil
		default:
			t.Fatal("unexpected request")
			return nil, nil
		}
	})
	sleeps := 0
	d.sleep = func(_ context.Context, x time.Duration) error {
		if x != 5*time.Second {
			t.Fatal(x)
		}
		sleeps++
		return nil
	}
	var out bytes.Buffer
	e := runUpload(context.Background(), uploadArgs("--fail-on", "high", "--json"), &out, d)
	assertUploadCode(t, e, 3)
	if calls != 6 || sleeps != 1 {
		t.Fatal(calls, sleeps)
	}
	assertUploadSafe(t, out.String(), e)
	var result struct {
		ExitCode int `json:"exit_code"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.ExitCode != 3 {
		t.Fatal(out.String())
	}
}
func TestUploadFinalStatesAndScope(t *testing.T) {
	for _, tc := range []struct {
		status, findings string
		code             int
	}{{"failed", "", 2}, {"succeeded", `{"data":[],"next_cursor":null}`, 0}, {"succeeded", `{"error":{"code":"insufficient_scope","message":"SECRET_RESPONSE"}}`, 1}, {"SECRET_RESPONSE", "", 1}, {"succeeded", `{"data":[],"next_cursor":""}`, 1}, {"succeeded", `{"data":[],"next_cursor":"repeat"}`, 1}, {"succeeded", `{"data":[]}`, 1}} {
		calls := 0
		d := uploadTestDeps(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
			}
			if strings.Contains(r.URL.Path, "/analyses/") {
				return uploadResponse(200, `{"status":"`+tc.status+`"}`), nil
			}
			status := 200
			if strings.Contains(tc.findings, "insufficient_scope") {
				status = 403
			}
			return uploadResponse(status, tc.findings), nil
		})
		var out bytes.Buffer
		e := runUpload(context.Background(), uploadArgs("--fail-on", "critical", "--json"), &out, d)
		assertUploadCode(t, e, tc.code)
		assertUploadSafe(t, out.String(), e)
		if strings.Contains(tc.findings, "insufficient_scope") && e.Error() != uploadScope {
			t.Fatal(e)
		}
	}
}
func TestUploadTimeout(t *testing.T) {
	calls := 0
	d := uploadTestDeps(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
		}
		return uploadResponse(200, `{"status":"running"}`), nil
	})
	d.sleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	var out bytes.Buffer
	e := runUpload(context.Background(), uploadArgs("--wait"), &out, d)
	assertUploadCode(t, e, 4)
	assertUploadSafe(t, out.String(), e)
}

// Unix sockets keep real HTTP server tests usable in the existing offline
// network namespace, where TCP loopback need not be configured.
func uploadUnixServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "c7b-http-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "http.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	server.URL = "http://localhost"
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport}
	t.Cleanup(func() { transport.CloseIdleConnections(); server.Close() })
	return server, client
}
func TestUploadNoRedirectWithHTTPServer(t *testing.T) {
	redirectCalls := 0
	server, client := uploadUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirectCalls++
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Location", "http://localhost/target")
		w.WriteHeader(307)
	}))
	d := uploadTestDeps(nil)
	d.client = client
	var out bytes.Buffer
	e := runUpload(context.Background(), uploadArgs("--api-url", server.URL), &out, d)
	assertUploadCode(t, e, 1)
	if redirectCalls != 0 {
		t.Fatal("redirect followed")
	}
	assertUploadSafe(t, out.String(), e)
}
func TestUploadHTTPServerFindings(t *testing.T) {
	calls := 0
	server, client := uploadUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+testUploadKey {
			t.Fatal("authorization absent")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sboms":
			w.WriteHeader(202)
			fmt.Fprintf(w, `{"analysis_id":"%s"}`, testAnalysisID)
		case "/v1/analyses/" + testAnalysisID:
			fmt.Fprint(w, `{"status":"succeeded"}`)
		case "/v1/findings":
			if r.URL.Query().Get("cursor") == "" {
				fmt.Fprint(w, `{"data":[],"next_cursor":"last"}`)
			} else {
				fmt.Fprint(w, `{"data":[{}],"next_cursor":null}`)
			}
		default:
			t.Error("unexpected route")
			w.WriteHeader(404)
		}
	}))
	d := uploadTestDeps(nil)
	d.client = client
	var out bytes.Buffer
	e := runUpload(context.Background(), uploadArgs("--api-url", server.URL, "--fail-on", "critical", "--json"), &out, d)
	assertUploadCode(t, e, 3)
	if calls != 4 {
		t.Fatal(calls)
	}
	assertUploadSafe(t, out.String(), e)
}
func TestUploadCLIIntegrationAndTarget(t *testing.T) {
	d := uploadTestDeps(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("project_slug") != "widget" || r.URL.Query().Get("version") != "1" || r.URL.Query().Get("release_label") != "Build" {
			t.Fatal("target lost")
		}
		return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
	})
	var out bytes.Buffer
	e := runUpload(context.Background(), []string{"--sbom", "x", "--project-slug", "widget", "--version", "1", "--release-label", "Build"}, &out, d)
	assertUploadCode(t, e, 0)
	// Dispatch must reject upload flags without running the offline engine.
	e = runCLI(context.Background(), []string{"upload", "--api-key", testUploadKey}, &out, func(context.Context, string, string, string) ([]byte, error) {
		t.Fatal("engine invoked")
		return nil, nil
	}, time.Now)
	assertUploadCode(t, e, 1)
	assertUploadSafe(t, out.String(), e)
}

func TestUploadJSONConfigurationFailureAndStderr(t *testing.T) {
	for _, args := range [][]string{uploadArgs("--api-url", "https://user:SECRET_RESPONSE@example.test", "--json"), uploadArgs("--version", testUploadKey, "--json"), {"--json", "--unknown", testUploadKey}} {
		var stdout, stderr bytes.Buffer
		err := runUpload(context.Background(), args, &stdout, uploadTestDeps(nil))
		assertUploadCode(t, err, 1)
		fmt.Fprintln(&stderr, "cracken-sbom:", err)
		assertUploadSafe(t, stdout.String()+stderr.String(), nil)
		var result map[string]any
		if json.Unmarshal(stdout.Bytes(), &result) != nil {
			t.Fatal("JSON failure must emit exactly one object")
		}
	}
}
func TestUploadResponseCannotEchoSecrets(t *testing.T) {
	for _, body := range []string{`{"analysis_id":"SECRET_RESPONSE"}`, `{"analysis_id":"` + testUploadKey + `"}`, `[]`, `{}`, strings.Repeat("x", (1<<20)+1)} {
		d := uploadTestDeps(func(*http.Request) (*http.Response, error) { return uploadResponse(202, body), nil })
		var out bytes.Buffer
		e := runUpload(context.Background(), uploadArgs("--json"), &out, d)
		assertUploadCode(t, e, 1)
		assertUploadSafe(t, out.String(), e)
	}
}
func TestUploadRetryAfterDate(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if retryDelay(now.Add(12*time.Second).Format(http.TimeFormat), now) != 12*time.Second {
		t.Fatal("date ignored")
	}
	if retryDelay("bad", now) != time.Second {
		t.Fatal("invalid retry delay")
	}
}

func TestUploadRejectsCredentialAndMalformedCursors(t *testing.T) {
	for _, cursor := range []string{testUploadKey, "prefix-" + testUploadKey, "crk_invalid", strings.Repeat("a", 513), "next?key=value", "padding="} {
		calls := 0
		d := uploadTestDeps(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
			}
			if calls == 2 {
				return uploadResponse(200, `{"status":"succeeded"}`), nil
			}
			if calls == 3 {
				body, _ := json.Marshal(map[string]any{"data": []any{}, "next_cursor": cursor})
				return uploadResponse(200, string(body)), nil
			}
			t.Fatal("unsafe cursor caused another request")
			return nil, nil
		})
		var stdout, stderr bytes.Buffer
		err := runUpload(context.Background(), uploadArgs("--fail-on", "high", "--json"), &stdout, d)
		assertUploadCode(t, err, 1)
		fmt.Fprintln(&stderr, "cracken-sbom:", err)
		assertUploadSafe(t, stdout.String()+stderr.String(), nil)
		if calls != 3 {
			t.Fatalf("requests=%d want=3", calls)
		}
	}
}
func TestUploadRejectsNonContractAnalysisStatuses(t *testing.T) {
	for _, status := range []string{"parsing", "matching", "pending", "unknown"} {
		calls := 0
		d := uploadTestDeps(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return uploadResponse(202, `{"analysis_id":"`+testAnalysisID+`"}`), nil
			}
			return uploadResponse(200, `{"status":"`+status+`"}`), nil
		})
		var out bytes.Buffer
		err := runUpload(context.Background(), uploadArgs("--wait", "--json"), &out, d)
		assertUploadCode(t, err, 1)
		if calls != 2 {
			t.Fatal("invalid status continued polling")
		}
		assertUploadSafe(t, out.String(), err)
	}
}

func TestUploadMainErrorOutputUsesParsedJSONFlag(t *testing.T) {
	for _, tc := range []struct {
		flags []string
		json  bool
	}{
		{[]string{"--json"}, true},
		{[]string{"--json=false"}, false},
		{[]string{"--json", "--json=false"}, false},
		{[]string{"--json=false", "--json=true"}, true},
		{[]string{"--release-label", "--json"}, false},
	} {
		args := uploadArgs(tc.flags...)
		d := uploadTestDeps(func(*http.Request) (*http.Response, error) {
			return uploadResponse(401, `{"error":"SECRET_RESPONSE"}`), nil
		})
		var stdout, stderr bytes.Buffer
		err := runUpload(context.Background(), args, &stdout, d)
		assertUploadCode(t, err, 1)
		writeCLIError(append([]string{"upload"}, args...), &stderr, err)
		combined := stdout.String() + stderr.String()
		assertUploadSafe(t, combined, nil)
		if tc.json {
			if stderr.Len() != 0 {
				t.Fatal("JSON mode printed human stderr")
			}
			var object map[string]any
			if json.Unmarshal([]byte(combined), &object) != nil {
				t.Fatal("combined output is not one JSON object")
			}
		} else if stderr.Len() == 0 {
			t.Fatal("human mode omitted error")
		}
	}
}
