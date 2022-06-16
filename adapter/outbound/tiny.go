package outbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

const (
	Method = "[M]"
	Host   = "[H]"
	HostP  = "[H_P]"
	Uri    = "[U]"
	Url    = "[url]"
	V      = "[V]"
)

type TinyConfig struct {
	HttpOpts  TinyOpts
	HttpsOpts TinyOpts
}

type Tiny struct {
	*Base
	httpOpts  TinyOpts
	httpsOpts TinyOpts
}

type TinyOpts struct {
	Server    string   `proxy:"server"`
	Port      int      `proxy:"port"`
	HttpDel   []string `proxy:"http-del,omitempty"`
	HttpFirst string   `proxy:"http-first"`
}

type tinyHttpConn struct {
	net.Conn
	cfg    *TinyConfig
	reader *bufio.Reader
}

type TinyOption struct {
	BasicOption
	Name      string   `proxy:"name"`
	HttpOpts  TinyOpts `proxy:"http-opts,omitempty"`
	HttpsOpts TinyOpts `proxy:"https-opts,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (h *Tiny) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	cfg := &TinyConfig{
		HttpsOpts: h.httpsOpts,
		HttpOpts:  h.httpOpts,
	}
	c = StreamHTTPConn(c, cfg)
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Tiny) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	if metadata.DstPort == "80" {
		h.addr = net.JoinHostPort(h.httpOpts.Server, strconv.Itoa(h.httpOpts.Port))
	}
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

// Write implements io.Writer.
func (hc *tinyHttpConn) Write(d []byte) (int, error) {
	//if (!hc.whandshake && hc.cfg.Protocol == "https") || (hc.cfg.Protocol == "http" && isHttpHeader(d)) {
	//	method, uri, version, host, ok := parseRequestLine(d)
	//	if !ok {
	//		return hc.Conn.Write(d)
	//	}
	//	b := delFirst(d)
	//	split := strings.Split(hc.cfg.Del, ",")
	//	b = delHeader(b, split)
	//	httpFirst := hc.cfg.HttpOpts.HttpFirst
	//	httpFirst = strings.ReplaceAll(httpFirst, Method, string(method))
	//	httpFirst = strings.ReplaceAll(httpFirst, Uri, string(uri))
	//	httpFirst = strings.ReplaceAll(httpFirst, Host, string(host))
	//	httpFirst = strings.ReplaceAll(httpFirst, V, string(version))
	//	b = append([]byte(httpFirst), b...)
	//	hc.Conn.Write(b)
	//} else {
	return hc.Conn.Write(d)
	//}
	//return len(d), nil
}

func delFirst(first []byte) []byte {
	index := bytes.IndexByte(first, '\n')
	first = first[index+1:]
	return first
}

func delHeader(first []byte, replaceWord []string) []byte {
	text := string(first)
	for _, s := range replaceWord {
		if s == "" {
			continue
		}
		r := regexp.MustCompile(s + `.*\n`)
		text = r.ReplaceAllString(text, "")
	}
	return []byte(text)
}

func isHttpHeader(header []byte) bool {
	if bytes.HasPrefix(header, []byte("CONNECT")) == true ||
		bytes.HasPrefix(header, []byte("GET")) == true ||
		bytes.HasPrefix(header, []byte("POST")) == true ||
		bytes.HasPrefix(header, []byte("HEAD")) == true ||
		bytes.HasPrefix(header, []byte("PUT")) == true ||
		bytes.HasPrefix(header, []byte("COPY")) == true ||
		bytes.HasPrefix(header, []byte("DELETE")) == true ||
		bytes.HasPrefix(header, []byte("MOVE")) == true ||
		bytes.HasPrefix(header, []byte("OPTIONS")) == true ||
		bytes.HasPrefix(header, []byte("LINK")) == true ||
		bytes.HasPrefix(header, []byte("UNLINK")) == true ||
		bytes.HasPrefix(header, []byte("TRACE")) == true ||
		bytes.HasPrefix(header, []byte("PATCH")) == true ||
		bytes.HasPrefix(header, []byte("WRAPPED")) == true {
		return true
	}
	return false
}

func (hc *tinyHttpConn) shakeHand(addr string) error {
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

	if err := req.Write(hc); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(hc), req)
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

func parseRequestLine(payload []byte) (method []byte, uri []byte, version []byte, host []byte, ok bool) {
	firstIndex := bytes.IndexByte(payload, '\n')
	firstLine := payload[:firstIndex-1]
	s1 := bytes.IndexByte(firstLine, ' ')
	s2 := bytes.IndexByte(firstLine[s1+1:], ' ')
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	header := payload[firstIndex+1:]
	hostKey := []byte("Host: ")
	s3 := bytes.Index(header, hostKey)
	if s3 == -1 {
		return
	}
	s4 := bytes.IndexByte(header[s3:], '\n')
	if s4 == -1 {
		return
	}
	s5 := s3 + len(hostKey)
	s6 := s3 + s4 - 1
	return firstLine[:s1], firstLine[s1+1 : s2], firstLine[s2+1:], header[s5:s6], true
}

func StreamHTTPConn(conn net.Conn, cfg *TinyConfig) net.Conn {
	t := &tinyHttpConn{
		Conn: conn,
		cfg:  cfg,
	}
	t.shakeHand(cfg.HttpsOpts.Server)
	return t
}

func NewTiny(option TinyOption) *Tiny {
	return &Tiny{
		Base: &Base{
			name:  option.Name,
			tp:    C.Tiny,
			iface: option.Interface,
		},
		httpOpts:  option.HttpOpts,
		httpsOpts: option.HttpsOpts,
	}
}
