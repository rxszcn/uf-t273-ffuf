package runner

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// gzipBomb returns a gzip stream that decompresses to `decompressed` bytes of
// zeros. The compressed form is tiny (zeros compress ~1000x), so the test moves
// almost no data over the wire while forcing a large decompression.
func gzipBomb(t *testing.T, decompressed int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	chunk := make([]byte, 1<<20) // 1 MiB of zeros, reused
	for written := 0; written < decompressed; {
		n := len(chunk)
		if r := decompressed - written; r < n {
			n = r
		}
		if _, err := zw.Write(chunk[:n]); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		written += n
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func runnerFor(t *testing.T, url string) (ffuf.RunnerProvider, ffuf.Request) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conf := ffuf.NewConfig(ctx, cancel)
	conf.Method = "GET"
	runner := NewSimpleRunner(&conf, false)
	req := ffuf.NewRequest(&conf)
	req.Method = "GET"
	req.Url = url
	return runner, req
}

// A malicious server returning a decompression bomb must not be read into memory
// unbounded. The response is capped at MAX_DOWNLOAD_SIZE and marked Cancelled
// rather than OOM-killing the process. Regression test for the gzip-bomb DoS
// (CWE-409): before the fix, io.ReadAll on the decompressed stream had no bound.
func TestExecute_GzipBombIsCapped(t *testing.T) {
	const decompressed = 64 << 20 // 64 MiB, well over the 5 MiB cap
	bomb := gzipBomb(t, decompressed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(bomb)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bomb)
	}))
	defer srv.Close()

	// Path 1: default client. The transport adds Accept-Encoding: gzip itself,
	// transparently decodes, and strips Content-Encoding/Content-Length, so the
	// header-based guard never fires. The LimitReader is what saves us.
	t.Run("transparent transport decode", func(t *testing.T) {
		runner, req := runnerFor(t, srv.URL+"/")
		resp, err := runner.Execute(&req)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if !resp.Cancelled {
			t.Fatalf("expected cancelled response, got %d bytes of data", len(resp.Data))
		}
		if len(resp.Data) > MAX_DOWNLOAD_SIZE {
			t.Fatalf("read %d bytes, must not exceed MAX_DOWNLOAD_SIZE (%d)", len(resp.Data), MAX_DOWNLOAD_SIZE)
		}
	})

	// Path 2: client sends its own Accept-Encoding, so the transport does NOT
	// auto-decode. Content-Encoding: gzip survives and Content-Length reflects the
	// small compressed size, passing the guard, so the manual decoder + LimitReader
	// must catch it.
	t.Run("manual decode with preserved headers", func(t *testing.T) {
		runner, req := runnerFor(t, srv.URL+"/")
		req.Headers["Accept-Encoding"] = "gzip"
		resp, err := runner.Execute(&req)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if !resp.Cancelled {
			t.Fatalf("expected cancelled response, got %d bytes of data", len(resp.Data))
		}
		if len(resp.Data) > MAX_DOWNLOAD_SIZE {
			t.Fatalf("read %d bytes, must not exceed MAX_DOWNLOAD_SIZE (%d)", len(resp.Data), MAX_DOWNLOAD_SIZE)
		}
	})
}

// A normal, small response must still be read in full and not cancelled, so the
// size cap does not regress ordinary fuzzing behaviour.
func TestExecute_NormalResponseUnaffected(t *testing.T) {
	body := []byte("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	runner, req := runnerFor(t, srv.URL+"/")
	resp, err := runner.Execute(&req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Cancelled {
		t.Fatal("normal response must not be cancelled")
	}
	if !bytes.Equal(resp.Data, body) {
		t.Fatalf("body = %q, want %q", resp.Data, body)
	}
}

// chunkedBodyServer streams `total` bytes with no Content-Length, so the response
// is framed chunked and the numeric size guard cannot fire.
func chunkedBodyServer(t *testing.T, total int) *httptest.Server {
	t.Helper()
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for written := 0; written < total; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
}

func runnerWithConfig(t *testing.T, url string, mutate func(*ffuf.Config)) (ffuf.RunnerProvider, ffuf.Request) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conf := ffuf.NewConfig(ctx, cancel)
	conf.Method = "GET"
	if mutate != nil {
		mutate(&conf)
	}
	runner := NewSimpleRunner(&conf, false)
	req := ffuf.NewRequest(&conf)
	req.Method = "GET"
	req.Url = url
	return runner, req
}

// allocatedBy reports how many bytes were allocated while fn ran.
func allocatedBy(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The -od and -audit-log snapshot path takes its own copy of the response body,
// and it runs before the LimitReader that bounds resp.Data. Without a bound of its
// own it reads an attacker-chosen amount into memory, so the size cap held for
// resp.Data but not for resp.Raw. Regression test for that: with either output
// feature enabled, a body far over the cap must not be materialised.
func TestExecute_SnapshotIsBoundedWithOutputFeatures(t *testing.T) {
	const body = 64 << 20 // 64 MiB against a 5 MiB cap
	// The ceiling is a multiple of the body, not an absolute figure. The test origin
	// runs in this process and allocates the body it streams, so roughly one body's
	// worth is charged here no matter how little the client reads; the race detector
	// adds more on top. The signal is the multiple: bounded stays near that floor,
	// unbounded allocates several times the body because it buffers, copies and
	// re-serialises it.
	const allocCeiling = 2 * body

	cases := []struct {
		name   string
		mutate func(*ffuf.Config)
	}{
		{"output directory", func(c *ffuf.Config) { c.OutputDirectory = t.TempDir() }},
		{"audit log", func(c *ffuf.Config) { c.AuditLog = filepath.Join(t.TempDir(), "audit.log") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := chunkedBodyServer(t, body)
			defer srv.Close()

			runner, req := runnerWithConfig(t, srv.URL+"/", tc.mutate)
			var resp ffuf.Response
			allocated := allocatedBy(func() {
				var err error
				resp, err = runner.Execute(&req)
				if err != nil {
					t.Fatalf("execute: %v", err)
				}
			})

			if allocated > allocCeiling {
				t.Errorf("allocated %d bytes for a %d byte body, want at most %d; the snapshot is reading past the cap",
					allocated, body, allocCeiling)
			}
			if len(resp.Raw) > MAX_DOWNLOAD_SIZE {
				t.Errorf("resp.Raw is %d bytes, must not exceed MAX_DOWNLOAD_SIZE (%d)", len(resp.Raw), MAX_DOWNLOAD_SIZE)
			}
			if !resp.Cancelled {
				t.Error("expected an over-cap response to be cancelled")
			}
		})
	}
}

// A gzip bomb reaches the same snapshot path: the transport requests gzip itself,
// decompresses transparently and strips Content-Length, so the numeric guard is
// skipped and the snapshot sees the expanded stream.
func TestExecute_SnapshotIsBoundedForGzipBomb(t *testing.T) {
	const decompressed = 64 << 20
	bomb := gzipBomb(t, decompressed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bomb)
	}))
	defer srv.Close()

	runner, req := runnerWithConfig(t, srv.URL+"/", func(c *ffuf.Config) {
		c.OutputDirectory = t.TempDir()
	})
	resp, err := runner.Execute(&req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(resp.Raw) > MAX_DOWNLOAD_SIZE {
		t.Errorf("resp.Raw is %d bytes, must not exceed MAX_DOWNLOAD_SIZE (%d)", len(resp.Raw), MAX_DOWNLOAD_SIZE)
	}
}

// A response within the cap must still be captured in full, so the size bound does
// not quietly truncate ordinary -od output.
func TestExecute_SnapshotKeptForNormalResponse(t *testing.T) {
	body := []byte("hello world")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	runner, req := runnerWithConfig(t, srv.URL+"/", func(c *ffuf.Config) {
		c.OutputDirectory = t.TempDir()
	})
	resp, err := runner.Execute(&req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Cancelled {
		t.Fatal("a normal response must not be cancelled")
	}
	if !strings.Contains(resp.Raw, string(body)) {
		t.Errorf("resp.Raw does not contain the body: %q", resp.Raw)
	}
}

// -ignore-body used to live inside the Content-Length branch, so it did nothing for
// a chunked response. It must hold regardless of framing.
func TestExecute_IgnoreBodyAppliesToChunkedResponse(t *testing.T) {
	srv := chunkedBodyServer(t, 32<<10)
	defer srv.Close()

	runner, req := runnerWithConfig(t, srv.URL+"/", func(c *ffuf.Config) { c.IgnoreBody = true })
	resp, err := runner.Execute(&req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !resp.Cancelled {
		t.Error("expected the response to be cancelled")
	}
	if len(resp.Data) != 0 {
		t.Errorf("read %d bytes of body despite -ignore-body", len(resp.Data))
	}
}

// Moving the -ignore-body check must not lose the server-declared length, which the
// size filters read.
func TestExecute_IgnoreBodyKeepsContentLength(t *testing.T) {
	body := make([]byte, 32<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	runner, req := runnerWithConfig(t, srv.URL+"/", func(c *ffuf.Config) { c.IgnoreBody = true })
	resp, err := runner.Execute(&req)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !resp.Cancelled {
		t.Error("expected the response to be cancelled")
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(body))
	}
}

// Response headers sit outside MAX_DOWNLOAD_SIZE, so the transport needs its own
// ceiling; Go's default is 10 MB.
func TestNewSimpleRunner_BoundsResponseHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conf := ffuf.NewConfig(ctx, cancel)
	runner := NewSimpleRunner(&conf, false).(*SimpleRunner)

	transport, ok := runner.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", runner.client.Transport)
	}
	if transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("MaxResponseHeaderBytes is unset, response headers are bounded only by the net/http default")
	}
	if transport.MaxResponseHeaderBytes > 4<<20 {
		t.Errorf("MaxResponseHeaderBytes = %d, larger than intended", transport.MaxResponseHeaderBytes)
	}
}

// prepareRequest builds a base request spanning all four replacement surfaces
// (Method, header name, header value, Url, Data body) and runs Prepare once.
func prepareRequest(t *testing.T, input map[string][]byte, method, url, data string, headers map[string]string) ffuf.Request {
	t.Helper()
	runner, _ := runnerFor(t, "http://unused")
	base := ffuf.Request{
		Method:  method,
		Url:     url,
		Data:    []byte(data),
		Headers: make(map[string]string, len(headers)),
	}
	for k, v := range headers {
		base.Headers[k] = v
	}
	got, err := runner.Prepare(input, &base)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return got
}

// overlappingInput is the dual-dictionary minimal construction input: the FUZZ
// payload literally contains the other keyword's name (W2), which the old
// serial ReplaceAll loop could swallow on a second pass.
func overlappingInput() map[string][]byte {
	return map[string][]byte{
		"FUZZ": []byte("W2-x"),
		"W2":   []byte("second"),
	}
}

// TestPrepare_OverlappingValueConstructionIsUnique locks deterministic request
// construction for the dual-dictionary overlap case. The same input must always
// construct the same request, regardless of Go's randomized map iteration order:
// repeated construction yields exactly one distinct result on every surface.
// Before the fix the loop ranged the input map and re-ran ReplaceAll per
// keyword, so the same input produced two different URLs in drifting
// proportions.
func TestPrepare_OverlappingValueConstructionIsUnique(t *testing.T) {
	const (
		method  = "GEFUZZT"
		url     = "https://example.org/a/FUZZ/b/W2"
		data    = "body=FUZZ&w=W2"
		hdrName = "X-FUZZ-Name"
		hdrVal  = "val-FUZZ-W2"
	)
	headers := map[string]string{hdrName: hdrVal}
	input := overlappingInput()

	const runs = 100
	seenMethods := make(map[string]struct{}, runs)
	seenURLs := make(map[string]struct{}, runs)
	seenData := make(map[string]struct{}, runs)
	seenHeaderNames := make(map[string]struct{}, runs)
	seenHeaderValues := make(map[string]struct{}, runs)

	for i := 0; i < runs; i++ {
		got := prepareRequest(t, input, method, url, data, headers)
		seenMethods[got.Method] = struct{}{}
		seenURLs[got.Url] = struct{}{}
		seenData[string(got.Data)] = struct{}{}
		for k, v := range got.Headers {
			seenHeaderNames[k] = struct{}{}
			seenHeaderValues[v] = struct{}{}
		}
	}

	if len(seenURLs) != 1 {
		t.Fatalf("distinct constructed URLs = %d, want 1: %v", len(seenURLs), keysOf(seenURLs))
	}
	if len(seenMethods) != 1 {
		t.Errorf("distinct constructed Methods = %d, want 1: %v", len(seenMethods), keysOf(seenMethods))
	}
	if len(seenData) != 1 {
		t.Errorf("distinct constructed Data bodies = %d, want 1: %v", len(seenData), keysOf(seenData))
	}
	if len(seenHeaderNames) != 1 {
		t.Errorf("distinct constructed header names = %d, want 1: %v", len(seenHeaderNames), keysOf(seenHeaderNames))
	}
	if len(seenHeaderValues) != 1 {
		t.Errorf("distinct constructed header values = %d, want 1: %v", len(seenHeaderValues), keysOf(seenHeaderValues))
	}
}

// TestPrepare_PayloadKeepsLiteralForm locks the payload-preservation boundary:
// replacement is a single simultaneous pass, so text introduced by a
// replacement is never rescanned. The FUZZ payload "W2-x" must survive verbatim
// even though it contains the W2 keyword name; only the standalone W2 marker
// is replaced, on all four surfaces including the header name and header value.
func TestPrepare_PayloadKeepsLiteralForm(t *testing.T) {
	input := overlappingInput()
	got := prepareRequest(t, input,
		"GEFUZZT",
		"https://example.org/a/FUZZ/b/W2",
		"body=FUZZ&w=W2",
		map[string]string{"X-FUZZ-Name": "val-FUZZ-W2"},
	)

	wantURL := "https://example.org/a/W2-x/b/second"
	if got.Url != wantURL {
		t.Errorf("Url = %q, want %q (payload must keep its literal W2, standalone W2 replaced)", got.Url, wantURL)
	}
	if wantMethod := "GEW2-xT"; got.Method != wantMethod {
		t.Errorf("Method = %q, want %q", got.Method, wantMethod)
	}
	if wantData := "body=W2-x&w=second"; string(got.Data) != wantData {
		t.Errorf("Data = %q, want %q", string(got.Data), wantData)
	}
	wantHeaderName := "X-W2-X-Name"
	wantHeaderValue := "val-W2-x-second"
	if len(got.Headers) != 1 {
		t.Fatalf("headers = %v, want exactly one header", got.Headers)
	}
	for k, v := range got.Headers {
		if k != wantHeaderName {
			t.Errorf("header name = %q, want %q (keyword in header name replaced once, payload not rescanned)", k, wantHeaderName)
		}
		if v != wantHeaderValue {
			t.Errorf("header value = %q, want %q (payload kept, standalone keyword replaced)", v, wantHeaderValue)
		}
	}
}

// TestPrepare_NoOverlapControlUnchanged is the no-overlap control group: when
// no payload value contains another keyword's literal, the single-pass replacer
// must produce exactly the result the old per-keyword ReplaceAll loop did, so
// ordinary single-keyword and non-overlapping multi-wordlist scans are
// byte-for-byte unaffected. It also covers a single-keyword-only request.
func TestPrepare_NoOverlapControlUnchanged(t *testing.T) {
	cases := []struct {
		name    string
		input   map[string][]byte
		method  string
		url     string
		data    string
		headers map[string]string
		want    ffuf.Request
	}{
		{
			name:    "single keyword",
			input:   map[string][]byte{"FUZZ": []byte("admin")},
			method:  "GET",
			url:     "https://example.org/FUZZ",
			data:    "user=FUZZ",
			headers: map[string]string{"X-Trace": "FUZZ"},
			want: ffuf.Request{
				Method:  "GET",
				Url:     "https://example.org/admin",
				Data:    []byte("user=admin"),
				Headers: map[string]string{"X-Trace": "admin"},
			},
		},
		{
			name:    "non-overlapping dual dictionaries",
			input:   map[string][]byte{"PARAM": []byte("id"), "VAL": []byte("42")},
			method:  "POST",
			url:     "https://example.org/?PARAM=VAL",
			data:    "PARAM=VAL",
			headers: map[string]string{"X-PARAM": "VAL"},
			want: ffuf.Request{
				Method:  "POST",
				Url:     "https://example.org/?id=42",
				Data:    []byte("id=42"),
				Headers: map[string]string{"X-Id": "42"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := prepareRequest(t, tc.input, tc.method, tc.url, tc.data, tc.headers)
			if got.Method != tc.want.Method {
				t.Errorf("Method = %q, want %q", got.Method, tc.want.Method)
			}
			if got.Url != tc.want.Url {
				t.Errorf("Url = %q, want %q", got.Url, tc.want.Url)
			}
			if string(got.Data) != string(tc.want.Data) {
				t.Errorf("Data = %q, want %q", string(got.Data), string(tc.want.Data))
			}
			if len(got.Headers) != len(tc.want.Headers) {
				t.Fatalf("headers = %v, want %v", got.Headers, tc.want.Headers)
			}
			for k, v := range tc.want.Headers {
				if got.Headers[k] != v {
					t.Errorf("header %q = %q, want %q (got headers %v)", k, got.Headers[k], v, got.Headers)
				}
			}
		})
	}
}

// keysOf returns the sorted keys of a string set for failure messages.
func keysOf(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
