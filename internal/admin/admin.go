package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nem1989/hookbox/internal/config"
	"github.com/nem1989/hookbox/internal/server"
)

//go:embed static
var ui embed.FS

type panel struct {
	path, hash string
	mu sync.Mutex
}

func New(path, hash string) (http.Handler, error) {
	key, err := hex.DecodeString(hash)
	if err != nil || len(key) != sha256.Size {
		return nil, errors.New("HOOKBOX_ADMIN_SHA256 must contain a SHA-256 hex digest")
	}
	p := &panel{path: path, hash: strings.ToLower(hash)}
	files, err := fs.Sub(ui, "static")
	if err != nil { return nil, err }
	assets := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.URL.Path == "/api/config" {
			w.Header().Set("Cache-Control", "no-store")
			if subtle.ConstantTimeCompare([]byte(server.BearerHash(r)), []byte(p.hash)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Administrator token required", 401)
				return
			}
			p.config(w, r)
			return
		}
		switch r.URL.Path {
		case "/", "/index.html", "/app.js", "/app.css":
			assets.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}), nil
}

func readLimited(path string) ([]byte, fs.FileMode, error) {
	f, err := os.Open(path)
	if err != nil { return nil, 0, err }
	defer f.Close()
	info, err := f.Stat()
	if err != nil { return nil, 0, err }
	b, err := io.ReadAll(io.LimitReader(f, config.MaxSize+1))
	if len(b) > config.MaxSize { return nil, 0, errors.New("configuration too large") }
	return b, info.Mode().Perm(), err
}

func tag(b []byte) string {
	s := sha256.Sum256(b)
	return `"` + hex.EncodeToString(s[:]) + `"`
}

func (p *panel) config(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "PUT" {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", 405)
		return
	}
	var src []byte
	var err error
	if r.Method == "PUT" {
		src, err = io.ReadAll(http.MaxBytesReader(w, r.Body, config.MaxSize))
		if err != nil { http.Error(w, "Invalid configuration body or size", 413); return }
		if _, err := config.Load(src, filepath.Dir(p.path)); err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current, mode, err := readLimited(p.path)
	if err != nil { http.Error(w, "Cannot read configuration", 500); return }
	version := tag(current)
	if r.Method == "GET" {
		w.Header().Set("ETag", version)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(current)
		return
	}
	if r.Header.Get("If-Match") != version {
		http.Error(w, "Configuration changed. Reload before saving.", 412)
		return
	}
	if !bytes.Equal(src, current) {
		if err := replaceConfig(p.path, src, mode); err != nil {
			http.Error(w, "Cannot save configuration", 500)
			return
		}
	}
	w.Header().Set("ETag", tag(src))
	w.WriteHeader(http.StatusNoContent)
}

func replaceConfig(path string, b []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hookbox-config-*")
	if err != nil { return err }
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil { err = f.Chmod(mode) }
	if err == nil { err = f.Sync() }
	closeErr := f.Close()
	if err != nil { return err }
	if closeErr != nil { return closeErr }
	return installConfig(f.Name(), path)
}
