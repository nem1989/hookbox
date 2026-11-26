package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/nem1989/hookbox/internal/config"
)

var client = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableCompression = true
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}()

func Execute(ctx context.Context, a config.Action, payload json.RawMessage, expose bool) (map[string]any, error) {
	if a.Type == "command" {
		r, err := RunCommand(ctx, a, payload)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"type": r.Type, "exit_code": r.ExitCode, "output_truncated": r.Truncated}
		if expose {
			result["stdout"], result["stderr"] = r.Stdout, r.Stderr
		}
		return result, nil
	}
	if a.Type != "http" {
		return nil, errors.New("unknown action")
	}
	ctx, cancel := context.WithTimeout(ctx, config.Timeout(a.Timeout))
	defer cancel()
	body := a.Body
	if a.Forward {
		body = payload
		if len(body) == 0 {
			body = json.RawMessage("null")
		}
	}
	failed := &Error{"http_failed", "HTTP action could not be completed.", 502}
	req, err := http.NewRequestWithContext(ctx, a.Method, a.URL, bytes.NewReader(body))
	if err != nil {
		return nil, failed
	}
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextError(ctx)
		}
		return nil, failed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{"http_failed", "HTTP action returned an unsuccessful status.", 502}
	}
	for _, value := range resp.Header.Values("Content-Encoding") {
		if !strings.EqualFold(strings.TrimSpace(value), "identity") {
			return nil, &Error{"http_encoding", "HTTP action returned an unsupported content encoding.", 502}
		}
	}
	output, err := io.ReadAll(io.LimitReader(resp.Body, a.MaxOutput+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextError(ctx)
		}
		return nil, failed
	}
	result := map[string]any{"type": "http", "status_code": resp.StatusCode, "output_truncated": int64(len(output)) > a.MaxOutput}
	if expose {
		result["body"] = outputText(output[:min(int64(len(output)), a.MaxOutput)])
	}
	return result, nil
}
