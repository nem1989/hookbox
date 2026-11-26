package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nem1989/hookbox/internal/actions"
	"github.com/nem1989/hookbox/internal/config"
)

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func BearerHash(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	p := strings.Fields(values[0])
	if len(p) != 2 || !strings.EqualFold(p[0], "Bearer") {
		return ""
	}
	sum := sha256.Sum256([]byte(p[1]))
	return hex.EncodeToString(sum[:])
}

func NewHooks(c *config.Config) http.Handler {
	paths := make(map[string]string)
	for name, h := range c.Hooks {
		if h.Enabled {
			paths[h.Path] = name
		}
	}
	slots := make(chan struct{}, c.General.Concurrent)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detail := func(status int, msg string) { JSON(w, status, map[string]string{"detail": msg}) }
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			JSON(w, 200, map[string]string{"status": "ok"})
			return
		}
		name, ok := paths[r.URL.Path]
		if !ok {
			detail(404, "Not Found")
			return
		}
		h := c.Hooks[name]
		if !slices.Contains(h.Methods, r.Method) {
			w.Header().Set("Allow", strings.Join(h.Methods, ", "))
			detail(405, "Method Not Allowed")
			return
		}
		digest := BearerHash(r)
		var token *config.Token
		for _, t := range c.Security.Tokens {
			if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(digest)) == 1 && t.Enabled && c.Security.Users[t.User].Enabled {
				token = t
			}
		}
		if token == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			detail(401, "Invalid or missing bearer token")
			return
		}
		roles := token.Roles
		if roles == nil {
			roles = c.Security.Users[token.User].Roles
		}
		if !slices.ContainsFunc(roles, func(role string) bool {
			ids := c.Security.Roles[role]
			return slices.Contains(ids, name) || slices.Contains(ids, "*")
		}) {
			detail(403, "Access denied")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			detail(503, "Execution capacity exhausted")
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(config.Timeout(c.General.BodyTimeout)))
		body, code, msg := readBody(w, r, c.General.MaxBody)
		_ = rc.SetReadDeadline(time.Time{})
		if code != 0 {
			detail(code, msg)
			return
		}
		var id [16]byte
		_, _ = rand.Read(id[:])
		requestID := hex.EncodeToString(id[:])
		w.Header().Set("X-Request-ID", requestID)
		results := make([]map[string]any, 0, len(h.Actions))
		reply := map[string]any{"request_id": requestID, "webhook": name, "status": "ok"}
		status := 200
		for i, a := range h.Actions {
			result, err := actions.Execute(r.Context(), a, body, h.Expose)
			if err != nil {
				var pub *actions.Error
				if !errors.As(err, &pub) {
					pub = &actions.Error{Code: "internal_error", Message: "Action execution failed", Status: 500}
				}
				status = pub.Status
				reply["status"], reply["failed_action"], reply["error"] = "error", i, pub
				break
			}
			results = append(results, result)
		}
		reply["results"] = results
		slog.Info("webhook", "request_id", requestID, "webhook", name, "user", token.User, "status", status)
		JSON(w, status, reply)
	})
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) (json.RawMessage, int, string) {
	if r.ContentLength > limit {
		return nil, 413, "Request body is too large"
	}
	if s := strings.Join(r.Header.Values("Content-Encoding"), ","); s != "" && !strings.EqualFold(s, "identity") {
		return nil, 415, "Content-Encoding is not supported"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var size *http.MaxBytesError
		var timeout net.Error
		if errors.As(err, &size) {
			return nil, 413, "Request body is too large"
		}
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, 408, "Request body timed out"
		}
		return nil, 400, "Invalid request body"
	}
	if len(body) == 0 {
		return json.RawMessage("null"), 0, ""
	}
	typ, _, _ := strings.Cut(strings.ToLower(r.Header.Get("Content-Type")), ";")
	typ = strings.TrimSpace(typ)
	if typ != "application/json" && !(strings.HasPrefix(typ, "application/") && strings.HasSuffix(typ, "+json")) {
		return nil, 415, "Expected application/json"
	}
	if !utf8.Valid(body) || !json.Valid(body) || !validEscapes(body) {
		return nil, 400, "Invalid UTF-8 JSON body"
	}
	// The original server rejects non-finite exponents but accepts arbitrary JSON integers.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 400, "Invalid UTF-8 JSON body"
		}
		if n, ok := tok.(json.Number); ok && strings.ContainsAny(string(n), ".eE") {
			if _, err := n.Float64(); err != nil {
				return nil, 400, "Invalid UTF-8 JSON body"
			}
		}
	}
	return body, 0, ""
}

// json.Valid accepts unpaired UTF-16 surrogates. Python's UTF-8 payload contract rejects them.
func validEscapes(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' { continue }
		i++
		if b[i] != 'u' { continue }
		var word [2]byte
		_, _ = hex.Decode(word[:], b[i+1:i+5])
		i += 4
		if word[0] < 0xd8 || word[0] > 0xdf { continue }
		if word[0] >= 0xdc || i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' { return false }
		_, _ = hex.Decode(word[:], b[i+3:i+7])
		if word[0] < 0xdc || word[0] > 0xdf { return false }
		i += 6
	}
	return true
}
