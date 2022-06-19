package outbound

import (
	"context"
	"fmt"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/tiny"
	"net"
	"strconv"
)

type Tiny struct {
	*Base
	HttpDel   []string
	HttpFirst string
	Connect   bool
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
	cfg := &tiny.HTTPConfig{
		Connect:   h.Connect,
		HttpDel:   h.HttpDel,
		HttpFirst: h.HttpFirst,
		Meta:      metadata,
	}
	c = tiny.StreamHTTPConn(c, *cfg)
	return c, nil
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
