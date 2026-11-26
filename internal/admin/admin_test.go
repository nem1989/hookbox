package admin

import (
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminConfig(t *testing.T){
	path:=filepath.Join(t.TempDir(),"config.yaml")
	original:="# keep comment\nwebhook: {}\nsecurity: {}\n"
	if err:=os.WriteFile(path,[]byte(original),0600);err!=nil{t.Fatal(err)}
	h,err:=New(path,fmt.Sprintf("%x",sha256.Sum256([]byte("admin"))));if err!=nil{t.Fatal(err)}
	call:=func(method,token,body,tag string)*httptest.ResponseRecorder{
		r:=httptest.NewRequest(method,"/api/config",strings.NewReader(body));r.Header.Set("Authorization","Bearer "+token);r.Header.Set("If-Match",tag)
		w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w
	}
	if call("GET","hook","","").Code!=401{t.Fatal("hook token accepted")}
	get:=call("GET","admin","","");etag:=get.Header().Get("ETag")
	if get.Code!=200||get.Body.String()!=original||etag==""{t.Fatal(get)}
	if call("PUT","admin","invalid",etag).Code!=422{t.Fatal("invalid configuration saved")}
	changed:="# changed\n"+original
	if call("PUT","admin",changed,etag).Code!=204{t.Fatal("save failed")}
	if call("PUT","admin",original,etag).Code!=412{t.Fatal("lost update")}
	data,err:=os.ReadFile(path);if err!=nil||string(data)!=changed{t.Fatal("incorrect file")}
}
