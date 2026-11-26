package config

import (
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "webhook:\n  test:\n    actions:\n      - type: command\n        command: [echo, '${ARG}']\nsecurity:\n  roles:\n    r: [test]\n"
func TestConfiguration(t *testing.T) {
	t.Setenv("ARG","value: [1]")
	dir:=t.TempDir()
	cfg,err:=Load([]byte(fixture),dir)
	if err!=nil {t.Fatal(err)}
	h:=cfg.Hooks["test"]
	if h.Path!="/hooks/test" || !h.Enabled || h.Actions[0].Cwd!=filepath.Clean(dir) || h.Actions[0].Command[1]!="value: [1]" { t.Fatal("incorrect defaults or expansion") }
	for _,bad:=range []string{
		fixture+"security: {}\n",
		strings.Replace(fixture,"type: command","type: command\n        url: https://example.org",1),
		strings.Replace(fixture,"r: [test]","r: [missing]",1),
		fixture+"---\n{}\n",
	}{if _,err:=Load([]byte(bad),dir);err==nil {t.Error("accepted invalid configuration")}}
}
