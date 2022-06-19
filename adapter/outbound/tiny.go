package outbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/log"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
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

type Tiny struct {
	*Base
	HttpDel   []string
	HttpFirst string
	Connect   bool
}

type tinyHttpConn struct {
	net.Conn
	cfg       *Tiny
	reader    *bufio.Reader
	connected bool
}

type TinyOption struct {
	BasicOption
	Name      string   `proxy:"name"`
	Server    string   `proxy:"server"`
	Port      int      `proxy:"port"`
	Connect   bool     `proxy:"connect,omitempty"`
	HttpDel   []string `proxy:"http-del,omitempty"`
	HttpFirst string   `proxy:"http-first"`
}

// StreamConn implements C.ProxyAdapter
func (h *Tiny) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	t := &tinyHttpConn{
		Conn: c,
		cfg:  h,
	}
	if h.Connect {
		if err := t.shakeHand(metadata, t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// DialContext implements C.ProxyAdapter
func (h *Tiny) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", h.addr, h.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = h.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
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
	if metadata.DstIP.IsValid() && metadata.DstPort != "" {
		addr = net.JoinHostPort(metadata.DstIP.String(), metadata.DstPort)
	}
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

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		hc.connected = true
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

func NewTiny(option TinyOption) *Tiny {
	return &Tiny{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Http,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},

		HttpDel:   option.HttpDel,
		HttpFirst: option.HttpFirst,
		Connect:   option.Connect,
	}
}
