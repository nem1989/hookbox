package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI(t *testing.T){
	var buf bytes.Buffer
	if err:=run([]string{"--generate-token"},&buf);err!=nil{t.Fatal(err)}
	var token map[string]string
	if err:=json.Unmarshal(buf.Bytes(),&token);err!=nil||len(token["token"])<32||token["sha256"]!=fmt.Sprintf("%x",sha256.Sum256([]byte(token["token"]))){t.Fatal("invalid token")}
	path:=filepath.Join(t.TempDir(),"config.yaml")
	if err:=os.WriteFile(path,[]byte("webhook: {}\nsecurity: {}"),0600);err!=nil{t.Fatal(err)}
	if err:=run([]string{"--check-config","--config",path},&buf);err!=nil{t.Fatal(err)}
	if err:=run([]string{"--check-config","--generate-token"},&buf);err==nil{t.Fatal("conflicting flags")}
}

// The sample distributed with the Go service must start without any legacy
// interpreter setting or previously provisioned webhook token.
func TestDistributedExampleConfig(t *testing.T) {
	for _, key := range []string{"PYTHON_EXECUTABLE", "WEBHOOK_TOKEN_SHA256"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join("..", "..", "config.example.yaml")
	if err := run([]string{"--config", path, "--check-config"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
