package vault

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

type Responce2Req struct {
	RequestURI   string
	ResponceCode int
	Delay        int
	Responce     string
}

type TestDoer struct {
	R2rChan chan Responce2Req
}

func NewTestDoer(requestNums int) *TestDoer {
	testDoer := &TestDoer{}
	testDoer.R2rChan = make(chan Responce2Req, requestNums)
	return testDoer
}

func (t *TestDoer) Close() {
	close(t.R2rChan)
}

func (t *TestDoer) httpCall(w http.ResponseWriter, req *http.Request) error {
	r2r := <-t.R2rChan
	if r2r.Delay > 0 {
		time.Sleep(time.Duration(r2r.Delay) * time.Second)
	}
	reqURI := req.URL.RequestURI()
	if reqURI != r2r.RequestURI {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	//FOR INTERNAL REVIEW PURPOSES
	if req.Method == "PUT" || req.Method == "POST" {
		bytes, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			return err
		}
		fmt.Printf("%s", string(bytes))
	}
	w.WriteHeader(r2r.ResponceCode)
	_, err := io.WriteString(w, r2r.Responce)
	if err != nil {
		return err
	}
	return nil
}

func (t *TestDoer) httpCallHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("content-type", "application/json")
	w.Header().Add("charset", "UTF-8")
	var err error
	switch req.Method {
	case "HEAD", "GET", "PUT", "DELETE":
		err = t.httpCall(w, req)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// testHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
func testHTTPServer(t *testing.T) (*api.Config, net.Listener, *TestDoer) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	testCreateDoer := NewTestDoer(5)

	server := &http.Server{Handler: http.HandlerFunc(testCreateDoer.httpCallHandler)}
	//nolint
	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln, testCreateDoer
}
