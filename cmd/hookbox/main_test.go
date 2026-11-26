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
