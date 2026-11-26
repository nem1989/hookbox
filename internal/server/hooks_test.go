package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nem1989/hookbox/internal/config"
)

func TestWebhookContract(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" { t.Error("incoming bearer forwarded") }
		io.Copy(w,r.Body)
	}))
	defer upstream.Close()
	c, err := config.Load([]byte(fmt.Sprintf(`webhook:
  echo:
    expose_output: true
    actions:
      - {type: http, url: '%s', forward_payload: true}
security:
  roles: {r: [echo]}
  users: {u: {roles: [r]}}
  tokens:
    yes_token: {user: u, sha256: '%x'}
    no_token: {user: u, sha256: '%x', roles: []}
`,upstream.URL,sha256.Sum256([]byte("yes")),sha256.Sum256([]byte("no")))),t.TempDir())
	if err != nil { t.Fatal(err) }
	h := NewHooks(context.Background(), c)
	for _, tc := range []struct{ method, path, token, media, body string; want int }{
		{"GET","/healthz","","","",200},{"GET","/hooks/echo","yes","","",405},
		{"POST","/missing","yes","","",404},{"POST","/hooks/echo","","","",401},
		{"POST","/hooks/echo","no","","",403},{"POST","/hooks/echo","yes","text/plain","123",415},
		{"POST","/hooks/echo","yes","application/json","[",400},
		{"POST","/hooks/echo","yes","application/json",`"\udfff"`,400},
		{"POST","/hooks/echo","yes","application/json",`1e999`,400},
		{"POST","/hooks/echo","yes","application/x+json",`{"text":"\ud83d\ude00"}`,200},
		{"POST","/hooks/echo","yes","","",200},
	} {
		r:=httptest.NewRequest(tc.method,tc.path,strings.NewReader(tc.body))
		r.Header.Set("Authorization","Bearer "+tc.token); r.Header.Set("Content-Type",tc.media)
		w:=httptest.NewRecorder();h.ServeHTTP(w,r)
		if w.Code!=tc.want {t.Errorf("%+v: %d %s",tc,w.Code,w.Body.String())}
		if w.Code==200 && tc.method=="POST" && (w.Header().Get("X-Request-ID")=="" || !strings.Contains(w.Body.String(),`"type":"http"`)){t.Fatal(w.Body)}
	}
}

func TestHTTPActionPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		switch r.URL.Path {
		case "/redirect": http.Redirect(w,r,"/should-not-run",302)
		case "/compressed": w.Header().Set("Content-Encoding","gzip")
		case "/slow": <-r.Context().Done()
		case "/should-not-run": t.Error("followed redirect")
		default: fmt.Fprint(w,"private")
		}
	}))
	defer upstream.Close()
	for _, tc:=range []struct{path string; want int; code string}{
		{"/",200,""},{"/redirect",502,"http_failed"},{"/compressed",502,"http_encoding"},{"/slow",504,"action_timeout"},
	}{
		c, err:=config.Load([]byte(fmt.Sprintf(`webhook:
  x:
    actions:
      - {type: http, url: '%s%s', timeout_seconds: 0.2, max_output_bytes: 2}
security:
  roles: {r: ['*']}
  users: {u: {roles: [r]}}
  tokens: {t: {user: u, sha256: '%x'}}
`,upstream.URL,tc.path,sha256.Sum256([]byte("token")))),t.TempDir())
		if err!=nil {t.Fatal(err)}
		r:=httptest.NewRequest("POST","/hooks/x",nil);r.Header.Set("Authorization","Bearer token")
		w:=httptest.NewRecorder();NewHooks(t.Context(), c).ServeHTTP(w,r)
		if w.Code!=tc.want || !strings.Contains(w.Body.String(),tc.code) || strings.Contains(w.Body.String(),`"body":`) {t.Fatalf("%s: %d %s",tc.path,w.Code,w.Body)}
	}
}

func TestBodyLimitAndSlots(t *testing.T) {
	started, finish := make(chan struct{}),make(chan struct{})
	upstream:=httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,*http.Request){close(started);<-finish}))
	defer upstream.Close()
	defer close(finish)
	cfg,err:=config.Load([]byte(fmt.Sprintf(`general: {max_body_bytes: 4, max_concurrent_requests: 1}
webhook: {w: {actions: [{type: http, url: '%s'}]}}
security: {roles: {r: [w]}, users: {u: {roles: [r]}}, tokens: {t: {user: u, sha256: '%x'}}}
`,upstream.URL,sha256.Sum256([]byte("t")))), t.TempDir())
	if err!=nil{t.Fatal(err)}
	h:=NewHooks(t.Context(), cfg)
	call:=func(body string)int{r:=httptest.NewRequest("POST","/hooks/w",strings.NewReader(body));r.Header.Set("Authorization","Bearer t");w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w.Code}
	if call("12345")!=413{t.Fatal("oversized request accepted")}
	go call("")
	select{case <-started: case <-time.After(5*time.Second):t.Fatal("request did not start")}
	if call("")!=503{t.Fatal("slot limit not enforced")}
}

func TestAcceptedActionFinishesAfterClientDisconnect(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done(): return
		case <-release: w.WriteHeader(http.StatusCreated)
		}
	}))
	defer upstream.Close()
	cfg, err := config.Load([]byte(fmt.Sprintf(`webhook: {w: {actions: [{type: http, url: '%s'}]}}
security: {roles: {r: [w]}, users: {u: {roles: [r]}}, tokens: {t: {user: u, sha256: '%x'}}}
`, upstream.URL, sha256.Sum256([]byte("test")))), t.TempDir())
	if err != nil { t.Fatal(err) }
	client, disconnect := context.WithCancel(t.Context())
	defer disconnect()
	r := httptest.NewRequest("POST", "/hooks/w", nil).WithContext(client)
	r.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { NewHooks(t.Context(), cfg).ServeHTTP(w, r); close(done) }()
	select {
	case <-started:
	case <-time.After(5*time.Second): close(release); t.Fatal("action did not start")
	}
	disconnect()
	close(release)
	<-done
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status_code":201`) { t.Fatal(w.Code, w.Body) }
}
