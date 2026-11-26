package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/nem1989/hookbox/internal/admin"
	"github.com/nem1989/hookbox/internal/config"
	"github.com/nem1989/hookbox/internal/server"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("hookbox", flag.ContinueOnError)
	file := flags.String("config", "config.yaml", "YAML configuration path")
	check := flags.Bool("check-config", false, "validate the YAML configuration and exit")
	generate := flags.Bool("generate-token", false, "generate a random token and SHA-256 digest")
	panelAddr := flags.String("admin-listen", "127.0.0.1:8081", "management listener (set HOOKBOX_ADMIN_SHA256 to enable)")
	if err := flags.Parse(args); err != nil { return err }
	if flags.NArg() != 0 || (*check && *generate) { return errors.New("invalid arguments") }
	if *generate {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil { return err }
		token := base64.RawURLEncoding.EncodeToString(raw[:])
		hash := sha256.Sum256([]byte(token))
		return json.NewEncoder(out).Encode(map[string]string{"token": token, "sha256": hex.EncodeToString(hash[:])})
	}
	path, err := filepath.Abs(*file)
	if err != nil { return err }
	path, err = filepath.EvalSymlinks(path)
	if err != nil { return errors.New("cannot resolve configuration file") }
	f, err := os.Open(path)
	if err != nil { return errors.New("cannot open configuration") }
	b, err := io.ReadAll(io.LimitReader(f, config.MaxSize+1))
	f.Close()
	if err != nil { return errors.New("cannot read configuration") }
	c, err := config.Load(b, filepath.Dir(path))
	if err != nil { return fmt.Errorf("configuration error: %w", err) }
	if *check {
		_, err = fmt.Fprintln(out, "Configuration is valid")
		return err
	}
	levels := map[string]slog.Level{"debug": slog.LevelDebug, "warning": slog.LevelWarn, "error": slog.LevelError, "critical": slog.LevelError+4}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levels[c.General.Level]})))
	var panel http.Handler
	if hash := os.Getenv("HOOKBOX_ADMIN_SHA256"); hash != "" {
		for _, t := range c.Security.Tokens {
			if equalHash(t.Hash, hash) { return errors.New("management and webhook tokens must be distinct") }
		}
		panel, err = admin.New(path, hash)
		if err != nil { return err }
	}
	return platformRun(func(ctx context.Context) error { return serve(ctx, c, panel, *panelAddr) })
}

func equalHash(first, second string) bool {
	a, err := hex.DecodeString(first)
	if err != nil { return false }
	b, err := hex.DecodeString(second)
	return err == nil && string(a) == string(b)
}

func consoleRun(start func(context.Context) error) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return start(ctx)
}

func serve(ctx context.Context, c *config.Config, panel http.Handler, panelAddr string) error {
	type endpoint struct { addr string; h http.Handler }
	list := []endpoint{{net.JoinHostPort(c.General.Host, strconv.Itoa(c.General.Port)), server.NewHooks(c)}}
	if panel != nil { list = append(list, endpoint{panelAddr, panel}) }
	var certs *tls.Config
	if ssl := c.General.SSL; ssl != nil {
		cert, err := tls.LoadX509KeyPair(ssl.Cert, ssl.Key)
		if err != nil { return errors.New("cannot load TLS certificate and key") }
		certs = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	var listeners []net.Listener
	for _, item := range list {
		l, err := net.Listen("tcp", item.addr)
		if err != nil { return err }
		defer l.Close()
		if certs != nil { l = tls.NewListener(l, certs) }
		listeners = append(listeners, l)
	}
	serverCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, len(list))
	servers := make([]*http.Server, 0, len(list))
	for i, item := range list {
		srv := &http.Server{Handler: item.h, ReadHeaderTimeout: 10*time.Second, IdleTimeout: time.Minute,
			BaseContext: func(net.Listener) context.Context { return serverCtx }}
		if i > 0 { srv.ReadTimeout = 30*time.Second }
		servers = append(servers, srv)
		slog.Info("listening", "address", item.addr, "management", i > 0)
		go func(l net.Listener) { done <- srv.Serve(l) }(listeners[i])
	}
	var serveErr error
	select { case <-ctx.Done(): case serveErr = <-done: }
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil { _ = srv.Close() }
	}
	return serveErr
}
