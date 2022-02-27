package tiny

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type tinyHttpConn struct {
	net.Conn
	cfg        *HTTPConfig
	reader     *bufio.Reader
	whandshake bool
}

const (
	Method    = "[M]"
	Host      = "[H]"
	HostP     = "[H_P]"
	Uri       = "[U]"
	Url       = "[url]"
	V         = "[V]"
	maxLength = 8192
)

type HTTPConfig struct {
	RemoteAddress string
	Protocol      string
	Del           string
	First         string
}

// Write implements io.Writer.
func (hc *tinyHttpConn) Write(d []byte) (int, error) {
	if (!hc.whandshake && hc.cfg.Protocol == "https") || (hc.cfg.Protocol == "http" && isHttpHeader(d)) {
		method, uri, version, host, ok := parseRequestLine(d)
		if !ok {
			return hc.Conn.Write(d)
		}
		b := delFirst(d)
		split := strings.Split(hc.cfg.Del, ",")
		b = delHeader(b, split)
		httpFirst := hc.cfg.First
		httpFirst = strings.ReplaceAll(httpFirst, Method, string(method))
		httpFirst = strings.ReplaceAll(httpFirst, Uri, string(uri))
		httpFirst = strings.ReplaceAll(httpFirst, Host, string(host))
		httpFirst = strings.ReplaceAll(httpFirst, V, string(version))
		b = append([]byte(httpFirst), b...)
		hc.Conn.Write(b)
	} else {
		return hc.Conn.Write(d)
	}
	return len(d), nil
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
	hc.whandshake = true
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
	return firstLine[:s1], firstLine[s1+1 : s2], firstLine[s2+1:], header[s3+len(hostKey) : s3+s4], true
}

func StreamHTTPConn(conn net.Conn, cfg *HTTPConfig) net.Conn {
	t := &tinyHttpConn{
		Conn: conn,
		cfg:  cfg,
	}
	if cfg.Protocol == "https" {
		t.shakeHand(cfg.RemoteAddress)
	}
	return t
}
