package tiny

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	// refer to https://pkg.go.dev/net/http@master#pkg-constants
	methods          = [...]string{"get", "post", "head", "put", "delete", "options", "connect", "patch", "trace"}
	errNotHTTPMethod = errors.New("not an HTTP method")
)

const (
	Method = "[M]"
	Host   = "[H]"
	HostP  = "[H_P]"
	Uri    = "[U]"
	Url    = "[url]"
	V      = "[V]"
)

type HTTPConfig struct {
	//Server    string
	//Port      int
	Connect   bool
	HttpDel   []string
	HttpFirst string
	Meta      *C.Metadata
}
type tinyHttpConn struct {
	net.Conn
	cfg HTTPConfig
	//reader    *bufio.Reader
	connected bool
}

func StreamHTTPConn(conn net.Conn, cfg HTTPConfig) net.Conn {
	t := &tinyHttpConn{
		Conn: conn,
		cfg:  cfg,
	}
	if cfg.Connect {
		if err := t.shakeHand(cfg.Meta, t); err != nil {
			return nil
		}
	}
	return t
}

// Reader implements io.Reader.
func (hc *tinyHttpConn) Read(b []byte) (int, error) {
	return hc.Conn.Read(b)
}

// Write implements io.Writer.
func (hc *tinyHttpConn) Write(b []byte) (int, error) {
	err := isHttpHeader(b)
	if !hc.connected && err == nil {
		req, error := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewBuffer(b))))
		println(req.RequestURI)
		println(req.Host)
		println(req.Method)
		println(req.Proto)
		if error != nil {
			return hc.Conn.Write(b)
		}
		b := delFirst(b)
		b = delHeader(b, hc.cfg.HttpDel)
		httpFirst := hc.cfg.HttpFirst
		httpFirst = strings.ReplaceAll(httpFirst, Method, req.Method)
		httpFirst = strings.ReplaceAll(httpFirst, Uri, req.RequestURI)
		httpFirst = strings.ReplaceAll(httpFirst, Host, req.Host)
		httpFirst = strings.ReplaceAll(httpFirst, V, req.Proto)
		b = append([]byte(httpFirst), b...)
		hc.Conn.Write(b)
	} else {
		return hc.Conn.Write(b)
	}
	return len(b), nil
}

func (hc *tinyHttpConn) shakeHand(metadata *C.Metadata, rw io.ReadWriter) error {
	addr := metadata.RemoteAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host: addr,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}

	log.Infoln("CONNECT: " + addr)

	if err := req.Write(rw); err != nil {
		return err
	}

	hc.connected = true
	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func (hc *tinyHttpConn) Close() error {
	return hc.Conn.Close()
}

func delFirst(first []byte) []byte {
	index := bytes.IndexByte(first, '\n')
	first = first[index+1:]
	return first
}

func delHeader(first []byte, replaceWord []string) []byte {
	var dd []byte
	headers := bytes.Split(first, []byte{'\n'})
	for i := 1; i < len(headers); i++ {
		header := headers[i]
		if len(header) == 0 {
			break
		}
		parts := bytes.SplitN(header, []byte{':'}, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(string(parts[0]))
		var include = false
		for _, s := range replaceWord {
			if s == "" {
				continue
			}
			s = strings.ToLower(s)
			if key == s {
				include = true
			}
		}
		if !include {
			dd = append(dd, header...)
		}
	}
	dd = append(dd, []byte{'\n', '\n'}...)
	return dd
}

func isHttpHeader(b []byte) error {
	for _, m := range &methods {
		if len(b) >= len(m) && strings.EqualFold(string(b[:len(m)]), m) {
			return nil
		}

		if len(b) < len(m) {
			return errNotHTTPMethod
		}
	}
	return errNotHTTPMethod
}
