package provider

import (
	C "github.com/Dreamacro/clash/constant"
)

// Vehicle Type
const (
	File VehicleType = iota
	HTTP
	Compatible
)

// VehicleType defined
type VehicleType int

func (v VehicleType) String() string {
	switch v {
	case File:
		return "File"
	case HTTP:
		return "HTTP"
	case Compatible:
		return "Compatible"
	default:
		return "Unknown"
	}
}

type Vehicle interface {
	Read() ([]byte, error)
	Path() string
	Type() VehicleType
}

// Provider Type
const (
	Proxy ProviderType = iota
	Rule
)

// ProviderType defined
type ProviderType int

func (pt ProviderType) String() string {
	switch pt {
	case Proxy:
		return "Proxy"
	case Rule:
		return "Rule"
	default:
		return "Unknown"
	}
}

// Provider interface
type Provider interface {
	Name() string
	VehicleType() VehicleType
	Type() ProviderType
	Initial() error
	Update() error
}

// ProxyProvider interface
type ProxyProvider interface {
	Provider
	Proxies() []C.Proxy
	Touch()
	HealthCheck()
	Version() uint32
}

// Rule Type
const (
	Domain RuleType = iota
	IPCIDR
	Classical
)

// RuleType defined
type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case IPCIDR:
		return "IPCIDR"
	case Classical:
		return "Classical"
	default:
		return "Unknown"
	}
}

// RuleProvider interface
type RuleProvider interface {
	Provider
	Behavior() RuleType
	Match(*C.Metadata) bool
	ShouldResolveIP() bool
	AsRule(adaptor string) C.Rule
}
