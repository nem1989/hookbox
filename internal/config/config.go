package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type General struct {
	Host string `json:"host"`
	Port int `json:"port"`
	URL *string `json:"url"`
	SSL *TLS `json:"ssl"`
	Level string `json:"log_level"`
	MaxBody int64 `json:"max_body_bytes"`
	BodyTimeout float64 `json:"body_timeout_seconds"`
	Concurrent int `json:"max_concurrent_requests"`
}
type TLS struct { Cert string `json:"certfile"`; Key string `json:"keyfile"` }
type Config struct {
	General General `json:"general"`
	Hooks map[string]*Hook `json:"webhook"`
	Security *Security `json:"security"`
}
type Hook struct {
	Path string `json:"path"`
	Methods []string `json:"methods"`
	Enabled bool `json:"enabled"`
	Expose bool `json:"expose_output"`
	Actions []Action `json:"actions"`
}
type Security struct {
	Roles map[string][]string `json:"roles"`
	Users map[string]*User `json:"users"`
	Tokens map[string]*Token `json:"tokens"`
}
type User struct { Roles []string `json:"roles"`; Enabled bool `json:"enabled"` }
type Token struct {
	User string `json:"user"`
	Hash string `json:"sha256"`
	Roles []string `json:"roles"`
	Enabled bool `json:"enabled"`
}
type Action struct {
	Type string `json:"type"`
	Command []string `json:"command"`
	Cwd string `json:"cwd"`
	Env map[string]string `json:"env"`
	Stdin bool `json:"stdin_from_payload"`
	URL string `json:"url"`
	Method string `json:"method"`
	Headers map[string]string `json:"headers"`
	Body json.RawMessage `json:"body"`
	Forward bool `json:"forward_payload"`
	Timeout float64 `json:"timeout_seconds"`
	MaxOutput int64 `json:"max_output_bytes"`
}
var (
	nameRE = regexp.MustCompile(`^[a-zA-Z0-9][A-Za-z0-9_.-]*$`)
	pathRE = regexp.MustCompile(`^(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+$`)
	envRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	hashRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	headerRE = regexp.MustCompile("^[!#$%&'*+.^_`|~A-Za-z0-9-]+$")
)
const MaxSize = 4 << 20
func strict(data []byte, into any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(into)
}
func (h *Hook) UnmarshalJSON(b []byte) error {
	type raw Hook
	v := raw{Enabled:true, Methods:[]string{"POST"}}
	if err := strict(b,&v); err != nil { return err }
	*h = Hook(v); return nil
}
func (u *User) UnmarshalJSON(b []byte) error {
	type raw User; v := raw{Enabled:true}
	if err := strict(b,&v); err != nil { return err }; *u=User(v); return nil
}
func (t *Token) UnmarshalJSON(b []byte) error {
	type raw Token; v := raw{Enabled:true}
	if err := strict(b,&v); err != nil { return err }; *t=Token(v); return nil
}
func (a *Action) UnmarshalJSON(b []byte) error {
	type raw Action; v := raw{Stdin:true, Method:"POST", Timeout:30, MaxOutput:65536}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b,&fields); err != nil { return err }
	if err := strict(b,&v); err != nil { return err }
	allowed := []string{"type","timeout_seconds","max_output_bytes"}
	switch v.Type {
	case "command": allowed=append(allowed,"command","cwd","env","stdin_from_payload")
	case "http": allowed=append(allowed,"url","headers","method","body","forward_payload")
	default: return errors.New("invalid action type")
	}
	for k := range fields { if !slices.Contains(allowed,k) { return errors.New("unexpected action field") } }
	*a=Action(v); return nil
}

// Expand scalar values only. Keys and environment values are never reinterpreted as YAML.
func value(n *yaml.Node, budget *int, depth int) (any,error) {
	*budget--
	if *budget < 0 || depth>100 { return nil, errors.New("YAML too complex") }
	switch n.Kind {
	case yaml.AliasNode: return value(n.Alias,budget,depth+1)
	case yaml.MappingNode:
		m:=map[string]any{}
		for i:=0;i<len(n.Content);i+=2 {
			k:=n.Content[i]
			v,err:=value(n.Content[i+1],budget,depth+1); if err!=nil{return nil,err}
			if k.ShortTag()=="!!merge" {
				parents,ok:=v.([]any); if !ok {parents=[]any{v}}
				for _,p:=range parents { nested,ok:=p.(map[string]any);if !ok{return nil,errors.New("invalid YAML merge")};for key,item:=range nested {if _,dup:=m[key];dup{return nil,errors.New("duplicate YAML key")};m[key]=item} };continue
			}
			if k.Kind!=yaml.ScalarNode || k.ShortTag()!="!!str" {return nil,errors.New("invalid mapping key")}
			if _,dup:=m[k.Value];dup{return nil,errors.New("duplicate YAML key")};m[k.Value]=v
		};return m,nil
	case yaml.SequenceNode:
		a:=make([]any,0,len(n.Content));for _,child:=range n.Content {v,err:=value(child,budget,depth+1);if err!=nil{return nil,err};a=append(a,v)};return a,nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str":
			var err error
			s:=envRE.ReplaceAllStringFunc(n.Value,func(s string)string{v,ok:=os.LookupEnv(s[2:len(s)-1]);if !ok{err=errors.New("missing environment variable "+s[2:len(s)-1])};return v});return s,err
		case "!!int","!!float","!!bool","!!null":
			var v any; err:=n.Decode(&v);return v,err
		}
	}
	return nil,errors.New("unsupported YAML value")
}
func Load(data []byte,dir string)(*Config,error){
	if len(data)>MaxSize || !utf8.Valid(data){return nil,errors.New("invalid configuration encoding or size")}
	var doc yaml.Node
	d:=yaml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data,[]byte{0xef,0xbb,0xbf})))
	if err:=d.Decode(&doc);err!=nil||len(doc.Content)!=1{return nil,errors.New("invalid YAML document")}
	if err:=d.Decode(&yaml.Node{});err!=io.EOF{return nil,errors.New("expected a single YAML document")}
	budget:=200000
	v,err:=value(doc.Content[0],&budget,0);if err!=nil{return nil,err}
	b,err:=json.Marshal(v);if err!=nil{return nil,errors.New("invalid YAML value")}
	c:=&Config{General:General{Host:"127.0.0.1",Port:8080,Level:"info",MaxBody:1<<20,BodyTimeout:30,Concurrent:8}}
	if err:=strict(b,c);err!=nil{return nil,errors.New("configuration contains an unknown field or invalid type")}
	return c,c.validate(dir)
}
func absolute(dir,p string)string{if filepath.IsAbs(p){return p};return filepath.Join(dir,p)}
func validURL(s string)bool{
	u,e:=url.Parse(s);if e!=nil||u.Hostname()==""||u.User!=nil||u.Fragment!=""||(u.Scheme!="http"&&u.Scheme!="https")||strings.ContainsAny(s," \t\r\n"){return false}
	if p:=u.Port();p!=""{v,e:=strconv.Atoi(p);return e==nil&&v>=1&&v<=65535};return true
}
func Timeout(s float64)time.Duration{return time.Duration(s*float64(time.Second))}
func validSeconds(s float64)bool{return s>0&&s<float64(math.MaxInt64)/1e9&&Timeout(s)>0}
func (c *Config) validate(dir string)error{
	g:=&c.General
	if g.Host==""||strings.ContainsAny(g.Host," \r\n\t")||g.Port<1||g.Port>65535||g.Concurrent<1||g.MaxBody<1||!validSeconds(g.BodyTimeout)||!slices.Contains([]string{"critical","error","warning","info","debug"},g.Level)||(g.URL!=nil&&!validURL(*g.URL)){return errors.New("invalid general settings")}
	if g.SSL!=nil {if strings.TrimSpace(g.SSL.Key)==""||strings.TrimSpace(g.SSL.Cert)==""{return errors.New("invalid TLS paths")};g.SSL.Key=absolute(dir,g.SSL.Key);g.SSL.Cert=absolute(dir,g.SSL.Cert)}
	if c.Hooks==nil||c.Security==nil{return errors.New("webhook and security sections required")}
	paths:=map[string]bool{}
	for name,h:=range c.Hooks{
		if !nameRE.MatchString(name)||h==nil{return errors.New("invalid webhook")}
		if h.Path==""{h.Path="/hooks/"+name}
		if !pathRE.MatchString(h.Path)||h.Path=="/healthz"||paths[h.Path]||len(h.Methods)==0||len(h.Actions)==0{return fmt.Errorf("invalid webhook %s",name)}
		paths[h.Path]=true;seen:=map[string]bool{}
		for _,m:=range h.Methods{if seen[m]||!slices.Contains([]string{"POST","PATCH","PUT"},m){return errors.New("invalid webhook methods")};seen[m]=true}
		for i:=range h.Actions{if err:=h.Actions[i].validate(dir);err!=nil{return fmt.Errorf("%s action %d: %w",name,i,err)}}
	}
	s:=c.Security
	for r,hooks:=range s.Roles{if !nameRE.MatchString(r){return errors.New("invalid role")};for _,h:=range hooks{if h!="*"&&c.Hooks[h]==nil{return errors.New("unknown webhook in role")}}}
	for name,u:=range s.Users{if !nameRE.MatchString(name)||u==nil{return errors.New("invalid user")};for _,r:=range u.Roles{if _,ok:=s.Roles[r];!ok{return errors.New("unknown user role")}}}
	hashes:=map[string]bool{}
	for name,t:=range s.Tokens{if !nameRE.MatchString(name)||t==nil||s.Users[t.User]==nil||!hashRE.MatchString(t.Hash){return errors.New("invalid token")};t.Hash=strings.ToLower(t.Hash);if hashes[t.Hash]{return errors.New("duplicate token digest")};hashes[t.Hash]=true;for _,r:=range t.Roles{if !slices.Contains(s.Users[t.User].Roles,r){return errors.New("token exceeds user roles")}}}
	return nil
}
func(a *Action)validate(dir string)error{
	if !validSeconds(a.Timeout)||a.MaxOutput<1||a.MaxOutput==math.MaxInt64{return errors.New("invalid action limits")}
	if a.Type=="command"{
		if len(a.Command)==0||strings.TrimSpace(a.Command[0])==""{return errors.New("empty command")}
		for _,arg:=range a.Command{if strings.ContainsRune(arg,0){return errors.New("invalid command argument")}}
		for k,v:=range a.Env{if k==""||strings.ContainsAny(k,"=\x00")||strings.ContainsRune(v,0){return errors.New("invalid environment")}}
		a.Cwd=absolute(dir,a.Cwd);return nil
	}
	if !validURL(a.URL)||!slices.Contains([]string{"GET","POST","PUT","PATCH","DELETE"},a.Method)||(a.Forward&&a.Body!=nil){return errors.New("invalid HTTP action")}
	for k,v:=range a.Headers{if !headerRE.MatchString(k)||strings.IndexFunc(v,func(r rune)bool{return r<32&&r!='\t'||r>=127})>=0{return errors.New("invalid HTTP header")}}
	return nil
}
