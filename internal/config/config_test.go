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

func TestAdminPort(t *testing.T) {
    const base = "webhook: {}\nsecurity: {}\n"
    for _, tc := range []struct { general string; want int }{
        {"{}", 8081}, {"{port: 8090}", 8081}, {"{port: 8090, admin_port: 8091}", 8091},
        {"{admin_port: 1}", 1}, {"{admin_port: 65535}", 65535}, {"{admin_port: 0}", 0}, {"{admin_port: 65536}", 0},
    } {
        c, err := Load([]byte(base+"general: "+tc.general+"\n"), t.TempDir())
        if tc.want == 0 {
            if err == nil { t.Errorf("accepted %s",tc.general) }
        } else if err != nil || c.General.AdminPort != tc.want {
            t.Errorf("unexpected admin port for %s (error %v)",tc.general,err)
        }
    }
}
