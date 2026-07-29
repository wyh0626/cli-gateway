package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyh0626/cli-gateway/client/internal/branding"
)

func TestC0ManifestToDynamicExecution(t *testing.T) {
	var executions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer good-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"ok":false,"error":"E_AUTH_INVALID","message":"bad token"}`)
			return
		}
		switch request.URL.Path {
		case "/manifest":
			writer.Header().Set("ETag", `"manifest-1"`)
			_, _ = io.WriteString(writer, `{
				"cli":{"name":"cg"},
				"domains":[{"name":"demo","commands":[
					{"path":["item","get"],"summary":"get item","method":"GET","risk":"read","scope":"demo:read",
					 "flags":[{"name":"id","type":"string","in":"path","required":true}]},
					{"path":["item","delete"],"summary":"delete item","method":"DELETE","risk":"destroy","scope":"demo:delete",
					 "flags":[{"name":"id","type":"string","in":"path","required":true}]}
				]}],
				"etag":"manifest-1"
			}`)
		case "/exec/demo/item.get":
			executions.Add(1)
			var body struct {
				Args map[string]any `json:"args"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode body: %v", err)
			}
			if body.Args["id"] != "seed" {
				t.Errorf("args = %#v", body.Args)
			}
			_, _ = io.WriteString(writer, `{"ok":true,"status":200,"data":{"id":"seed","value":1}}`)
		case "/exec/demo/item.delete":
			executions.Add(1)
			if request.Header.Get("X-Cli-Gateway-Confirm") != "true" {
				t.Errorf("missing confirmation header")
			}
			_, _ = io.WriteString(writer, `{"ok":true,"status":200,"data":{"deleted":true}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	configDir := t.TempDir()
	cacheDir := t.TempDir()
	t.Setenv("CG_CONFIG_DIR", configDir)
	t.Setenv("CG_CACHE_DIR", cacheDir)
	environment := append(os.Environ(), "CG_TOKEN=good-token")
	baseArgs := []string{"--server", server.URL, "--region", "local"}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run(Options{
		Args: append(append([]string{}, baseArgs...), "update-commands"), Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 {
		t.Fatalf("update exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	args := append(append([]string{}, baseArgs...), "demo", "item", "get", "--id", "seed", "-o", "json")
	code = Run(Options{
		Args: args, Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 {
		t.Fatalf("get exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"id":"seed"`)) {
		t.Fatalf("stdout = %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	deleteArgs := append(append([]string{}, baseArgs...), "demo", "item", "delete", "--id", "seed")
	code = Run(Options{
		Args: deleteArgs, Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 2 {
		t.Fatalf("unconfirmed delete exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("executions after rejected delete = %d, want 1", got)
	}

	out.Reset()
	errOut.Reset()
	deleteArgs = append(deleteArgs, "--yes")
	code = Run(Options{
		Args: deleteArgs, Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 {
		t.Fatalf("confirmed delete exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if got := executions.Load(); got != 2 {
		t.Fatalf("executions = %d, want 2", got)
	}

	cacheMatches, err := filepath.Glob(filepath.Join(cacheDir, "local", "*", "*", "human", "manifest.json"))
	if err != nil || len(cacheMatches) != 1 {
		t.Fatalf("cache matches=%v err=%v", cacheMatches, err)
	}
}

func TestAuthenticationErrorExitCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"ok":false,"error":"E_AUTH_INVALID","message":"bad token"}`)
	}))
	defer server.Close()
	t.Setenv("CG_CONFIG_DIR", t.TempDir())
	t.Setenv("CG_CACHE_DIR", t.TempDir())
	var errOut bytes.Buffer
	code := Run(Options{
		Args:    []string{"--server", server.URL, "--region", "local", "update-commands"},
		Environ: append(os.Environ(), "CG_TOKEN=bad-token"),
		IO: IOStreams{
			In: bytes.NewBuffer(nil), Out: io.Discard, ErrOut: &errOut,
			IsTTY: func() bool { return false },
		},
	})
	if code != 3 {
		t.Fatalf("exit=%d stderr=%q", code, errOut.String())
	}
}

func TestCapabilitiesReturnsCurrentIdentityManifestAndCachesCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer good-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path != "/manifest" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("ETag", `"capabilities-1"`)
		_, _ = io.WriteString(writer, `{
			"cli":{"name":"cg"},
			"domains":[{"name":"inventory","commands":[{
				"path":["resource","list"],"summary":"List visible resources","method":"GET","risk":"read",
				"flags":[{"name":"page","type":"int","in":"query","default":1}]
			}]}],
			"etag":"capabilities-1"
		}`)
	}))
	defer server.Close()

	t.Setenv("CG_CONFIG_DIR", t.TempDir())
	t.Setenv("CG_CACHE_DIR", t.TempDir())
	environment := append(os.Environ(), "CG_TOKEN=good-token")
	baseArgs := []string{"--server", server.URL, "--region", "local"}
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := Run(Options{
		Args: append(append([]string{}, baseArgs...), "capabilities", "-o", "json"), Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 {
		t.Fatalf("capabilities exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var document struct {
		Domains []struct {
			Name     string `json:"name"`
			Commands []struct {
				Path  []string `json:"path"`
				Flags []struct {
					Name string `json:"name"`
				} `json:"flags"`
			} `json:"commands"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("decode capabilities: %v; output=%q", err, out.String())
	}
	if len(document.Domains) != 1 || document.Domains[0].Name != "inventory" ||
		len(document.Domains[0].Commands) != 1 ||
		strings.Join(document.Domains[0].Commands[0].Path, ".") != "resource.list" ||
		len(document.Domains[0].Commands[0].Flags) != 1 ||
		document.Domains[0].Commands[0].Flags[0].Name != "page" {
		t.Fatalf("capabilities document = %#v", document)
	}

	out.Reset()
	errOut.Reset()
	code = Run(Options{
		Args: append(append([]string{}, baseArgs...), "--help"), Environ: environment,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 || !strings.Contains(out.String(), "inventory") {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestHandleUserActionOpensHTTPSAfterExplicitConsent(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	var opened string
	f := &factory{
		io:      IOStreams{In: strings.NewReader("y\n"), Out: io.Discard, ErrOut: &errOut, IsTTY: func() bool { return true }},
		reader:  bufio.NewReader(strings.NewReader("y\n")),
		openURL: func(value string) error { opened = value; return nil },
	}
	raw := []byte(`{"data":{"userAction":{"type":"open_url","url":"https://accounts.vendor.example/oauth/authorize?state=app-1","message":"authorization required","completionCommand":"cg inventory application get --number app-1"}}}`)
	if err := f.handleUserAction(raw); err != nil {
		t.Fatal(err)
	}
	if opened != "https://accounts.vendor.example/oauth/authorize?state=app-1" {
		t.Fatalf("opened URL = %q", opened)
	}
	if !strings.Contains(errOut.String(), "cg inventory application get") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestHandleUserActionRejectsInsecureURL(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	opened := false
	f := &factory{
		io:      IOStreams{In: strings.NewReader("y\n"), Out: io.Discard, ErrOut: &errOut, IsTTY: func() bool { return true }},
		reader:  bufio.NewReader(strings.NewReader("y\n")),
		openURL: func(string) error { opened = true; return nil },
	}
	raw := []byte(`{"data":{"userAction":{"type":"open_url","url":"http://evil.example/oauth"}}}`)
	if err := f.handleUserAction(raw); err != nil {
		t.Fatal(err)
	}
	if opened || !strings.Contains(errOut.String(), "unsafe") {
		t.Fatalf("opened=%v stderr=%q", opened, errOut.String())
	}
}

func TestWriteCommandOpensUserActionAfterGatewayResponse(t *testing.T) {
	var opened string
	var executionSeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer good-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"ok":false,"error":"E_AUTH_INVALID","message":"bad token"}`)
			return
		}
		switch request.URL.Path {
		case "/manifest":
			_, _ = io.WriteString(writer, `{
				"cli":{"name":"cg"},
				"domains":[{"name":"inventory","commands":[{
					"path":["item","create"],"summary":"create item","method":"POST","risk":"write","confirm":true,
					"flags":[{"name":"name","type":"string","in":"body","required":true}]
				}]}],
				"etag":"item-create-1"
			}`)
		case "/exec/inventory/item.create":
			executionSeen.Store(true)
			if request.Header.Get("X-Cli-Gateway-Confirm") != "true" {
				t.Errorf("missing confirmation header")
			}
			var input struct {
				Args map[string]any `json:"args"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode request: %v", err)
			} else if input.Args["name"] != "server-42" {
				t.Errorf("name argument = %#v", input.Args["name"])
			}
			_, _ = io.WriteString(writer, `{
				"ok":true,"status":200,
				"data":{
					"success":true,
					"message":"request submitted",
					"data":{
						"requestId":"request-123",
						"status":"PENDING_USER_AUTHORIZATION",
						"userAction":{
							"type":"open_url",
							"url":"https://accounts.vendor.example/oauth/authorize?state=request-123",
							"message":"additional authorization is required",
							"completionCommand":"cg inventory request get --id request-123"
						}
					}
				}
			}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	t.Setenv("CG_CONFIG_DIR", t.TempDir())
	t.Setenv("CG_CACHE_DIR", t.TempDir())
	environment := append(os.Environ(), "CG_TOKEN=good-token")
	baseArgs := []string{"--server", server.URL, "--region", "local"}

	code := Run(Options{
		Args:    append(append([]string{}, baseArgs...), "update-commands"),
		Environ: environment,
		IO: IOStreams{
			In: bytes.NewBuffer(nil), Out: io.Discard, ErrOut: io.Discard,
			IsTTY: func() bool { return false },
		},
	})
	if code != 0 {
		t.Fatalf("update exit=%d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	confirmation := "inventory.item.create local " + strings.TrimPrefix(server.URL, "http://")
	code = Run(Options{
		Args:    append(append([]string{}, baseArgs...), "inventory", "item", "create", "-o", "json"),
		Environ: environment,
		IO: IOStreams{
			In: strings.NewReader("server-42\n" + confirmation + "\ny\n"), Out: &out, ErrOut: &errOut,
			IsTTY: func() bool { return true },
		},
		OpenURL: func(value string) error {
			opened = value
			return nil
		},
	})
	if code != 0 {
		t.Fatalf("apply exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !executionSeen.Load() {
		t.Fatal("gateway execution was not called")
	}
	if !strings.Contains(errOut.String(), "? name (--name):") ||
		!strings.Contains(errOut.String(), "type \""+confirmation+"\" to confirm") {
		t.Fatalf("interactive prompts missing: %q", errOut.String())
	}
	if opened != "https://accounts.vendor.example/oauth/authorize?state=request-123" {
		t.Fatalf("opened URL = %q", opened)
	}
	if !strings.Contains(errOut.String(), "cg inventory request get --id request-123") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestWhiteLabelClientUsesIsolatedBrandValues(t *testing.T) {
	var requestSeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/manifest" {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer acme-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		if request.Header.Get("User-Agent") != "acme-cli/"+version {
			t.Errorf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		requestSeen.Store(true)
		_, _ = io.WriteString(writer, `{"cli":{"name":"acme"},"domains":[],"etag":"acme-one"}`)
	}))
	defer server.Close()

	configDir := t.TempDir()
	cacheDir := t.TempDir()
	brand := branding.Config{Name: "acme"}
	environment := append(os.Environ(),
		"ACME_CONFIG_DIR="+configDir,
		"ACME_CACHE_DIR="+cacheDir,
		"ACME_TOKEN=acme-token",
		"CG_TOKEN=must-not-be-used",
	)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run(Options{
		Args:    []string{"--server", server.URL, "--region", "local", "update-commands"},
		Environ: environment,
		Brand:   brand,
		IO: IOStreams{
			In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut,
			IsTTY: func() bool { return false },
		},
	})
	if code != 0 || !requestSeen.Load() {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "rerun acme") {
		t.Fatalf("stdout = %q", out.String())
	}
	cacheMatches, err := filepath.Glob(filepath.Join(cacheDir, "local", "*", "*", "human", "manifest.json"))
	if err != nil || len(cacheMatches) != 1 {
		t.Fatalf("white-label cache matches=%v err=%v", cacheMatches, err)
	}

	out.Reset()
	errOut.Reset()
	code = Run(Options{
		Args: []string{"--help"}, Environ: environment, Brand: brand,
		IO: IOStreams{In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut, IsTTY: func() bool { return false }},
	})
	if code != 0 || !strings.Contains(out.String(), "Usage:\n  acme") {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestDynamicCommandCompletesDownstreamAuthorizationAndRetries(t *testing.T) {
	var authorized atomic.Bool
	var executions atomic.Int32
	var starts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer good-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"ok":false,"error":"E_AUTH_INVALID","message":"bad token"}`)
			return
		}
		switch request.URL.Path {
		case "/manifest":
			_, _ = io.WriteString(writer, `{
				"cli":{"name":"cg"},
				"domains":[{"name":"inventory","commands":[
					{"path":["list"],"summary":"list items","method":"GET","risk":"read","scope":"inventory:read","flags":[]}
				]}],
				"etag":"manifest-auth-code"
			}`)
		case "/exec/inventory/list":
			executions.Add(1)
			if !authorized.Load() {
				writer.WriteHeader(http.StatusPreconditionRequired)
				_, _ = io.WriteString(writer, `{"ok":false,"error":"E_DOWNSTREAM_AUTH_REQUIRED","message":"authorization required","hint":"run cg authorize inventory"}`)
				return
			}
			_, _ = io.WriteString(writer, `{"ok":true,"status":200,"data":{"items":["one"]}}`)
		case "/oauth/downstream/inventory/authorize":
			starts.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"domain": "inventory", "authorization_url": "https://provider.example/authorize?state=one",
				"expires_at": time.Now().Add(time.Minute).UTC(),
			})
		case "/oauth/downstream/inventory/status":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"domain": "inventory", "authorized": authorized.Load(),
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	t.Setenv("CG_CONFIG_DIR", t.TempDir())
	t.Setenv("CG_CACHE_DIR", t.TempDir())
	environment := append(os.Environ(), "CG_TOKEN=good-token")
	baseArgs := []string{"--server", server.URL, "--region", "local"}
	ioStreams := IOStreams{In: bytes.NewBuffer(nil), Out: io.Discard, ErrOut: io.Discard, IsTTY: func() bool { return false }}
	if code := Run(Options{Args: append(append([]string{}, baseArgs...), "update-commands"), Environ: environment, IO: ioStreams}); code != 0 {
		t.Fatalf("update-commands exit = %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	opened := make(chan string, 1)
	code := Run(Options{
		Args:    append(append([]string{}, baseArgs...), "inventory", "list", "-o", "json"),
		Environ: environment,
		IO: IOStreams{
			In: bytes.NewBuffer(nil), Out: &out, ErrOut: &errOut,
			IsTTY: func() bool { return true },
		},
		OpenURL: func(target string) error {
			opened <- target
			authorized.Store(true)
			return nil
		},
		AuthorizationPollInterval: time.Millisecond,
	})
	if code != 0 {
		t.Fatalf("execute exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	select {
	case target := <-opened:
		if target != "https://provider.example/authorize?state=one" {
			t.Fatalf("opened URL = %q", target)
		}
	default:
		t.Fatal("browser authorization URL was not opened")
	}
	if starts.Load() != 1 || executions.Load() != 2 {
		t.Fatalf("starts=%d executions=%d", starts.Load(), executions.Load())
	}
	if !strings.Contains(out.String(), "authorized downstream service inventory") ||
		!strings.Contains(out.String(), `"items":["one"]`) {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestNonTTYDoesNotStartInteractiveDownstreamAuthorization(t *testing.T) {
	var starts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/manifest":
			_, _ = fmt.Fprint(writer, `{"cli":{"name":"cg"},"domains":[{"name":"inventory","commands":[{"path":["list"],"method":"GET","risk":"read","scope":"inventory:read","flags":[]}]}],"etag":"one"}`)
		case "/exec/inventory/list":
			writer.WriteHeader(http.StatusPreconditionRequired)
			_, _ = fmt.Fprint(writer, `{"ok":false,"error":"E_DOWNSTREAM_AUTH_REQUIRED","message":"authorization required","hint":"run cg authorize inventory"}`)
		case "/oauth/downstream/inventory/authorize":
			starts.Add(1)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	t.Setenv("CG_CONFIG_DIR", t.TempDir())
	t.Setenv("CG_CACHE_DIR", t.TempDir())
	environment := append(os.Environ(), "CG_TOKEN=good-token")
	baseArgs := []string{"--server", server.URL, "--region", "local"}
	streams := IOStreams{In: bytes.NewBuffer(nil), Out: io.Discard, ErrOut: io.Discard, IsTTY: func() bool { return false }}
	if code := Run(Options{Args: append(append([]string{}, baseArgs...), "update-commands"), Environ: environment, IO: streams}); code != 0 {
		t.Fatalf("update exit=%d", code)
	}
	var errOut bytes.Buffer
	code := Run(Options{
		Args:    append(append([]string{}, baseArgs...), "inventory", "list"),
		Environ: environment,
		IO: IOStreams{
			In: bytes.NewBuffer(nil), Out: io.Discard, ErrOut: &errOut,
			IsTTY: func() bool { return false },
		},
	})
	if code == 0 || starts.Load() != 0 || !strings.Contains(errOut.String(), "run cg authorize inventory") {
		t.Fatalf("exit=%d starts=%d stderr=%q", code, starts.Load(), errOut.String())
	}
}

func TestDevNullIsNotTTY(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open dev null: %v", err)
	}
	defer file.Close()
	if isTerminal(file) {
		t.Fatal("os.DevNull was incorrectly detected as a terminal")
	}
}
