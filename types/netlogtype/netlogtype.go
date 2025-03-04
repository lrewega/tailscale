// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netlogtype defines types for network logging.
package netlogtype

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

// TODO(joetsai): Remove "omitempty" if "omitzero" is ever supported in both
// the v1 and v2 "json" packages.

// Message is the log message that captures network traffic.
type Message struct {
	NodeID tailcfg.StableNodeID `json:"nodeId" cbor:"0,keyasint"` // e.g., "n123456CNTRL"

	Start time.Time `json:"start" cbor:"12,keyasint"` // inclusive
	End   time.Time `json:"end"   cbor:"13,keyasint"` // inclusive

	VirtualTraffic  []ConnectionCounts `json:"virtualTraffic,omitempty"  cbor:"14,keyasint,omitempty"`
	SubnetTraffic   []ConnectionCounts `json:"subnetTraffic,omitempty"   cbor:"15,keyasint,omitempty"`
	ExitTraffic     []ConnectionCounts `json:"exitTraffic,omitempty"     cbor:"16,keyasint,omitempty"`
	PhysicalTraffic []ConnectionCounts `json:"physicalTraffic,omitempty" cbor:"17,keyasint,omitempty"`
}

const (
	maxJSONConnCounts = `{` + maxJSONConn + `,` + maxJSONCounts + `}`
	maxJSONConn       = `"proto":` + maxJSONProto + `,"src":` + maxJSONAddrPort + `,"dst":` + maxJSONAddrPort
	maxJSONProto      = `255`
	maxJSONAddrPort   = `"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"`
	maxJSONCounts     = `"txPkts":` + maxJSONCount + `,"txBytes":` + maxJSONCount + `,"rxPkts":` + maxJSONCount + `,"rxBytes":` + maxJSONCount
	maxJSONCount      = `18446744073709551615`

	// MaxConnectionCountsJSONSize is the maximum size of a ConnectionCounts
	// when it is serialized as JSON, assuming no superfluous whitespace.
	// It does not include the trailing comma that often appears when
	// this object is nested within an array.
	// It assumes that netip.Addr never has IPv6 zones.
	MaxConnectionCountsJSONSize = len(maxJSONConnCounts)

	maxCBORConnCounts = "\xbf" + maxCBORConn + maxCBORCounts + "\xff"
	maxCBORConn       = "\x00" + maxCBORProto + "\x01" + maxCBORAddrPort + "\x02" + maxCBORAddrPort
	maxCBORProto      = "\x18\xff"
	maxCBORAddrPort   = "\x52\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
	maxCBORCounts     = "\x0c" + maxCBORCount + "\x0d" + maxCBORCount + "\x0e" + maxCBORCount + "\x0f" + maxCBORCount
	maxCBORCount      = "\x1b\xff\xff\xff\xff\xff\xff\xff\xff"

	// MaxConnectionCountsCBORSize is the maximum size of a ConnectionCounts
	// when it is serialized as CBOR.
	// It assumes that netip.Addr never has IPv6 zones.
	MaxConnectionCountsCBORSize = len(maxCBORConnCounts)
)

// ConnectionCounts is a flattened struct of both a connection and counts.
type ConnectionCounts struct {
	Connection
	Counts
}

// Connection is a 5-tuple of proto, source and destination IP and port.
type Connection struct {
	Proto ipproto.Proto  `json:"proto,omitzero,omitempty" cbor:"0,keyasint,omitempty"`
	Src   netip.AddrPort `json:"src,omitzero,omitempty"   cbor:"1,keyasint,omitempty"`
	Dst   netip.AddrPort `json:"dst,omitzero,omitempty"   cbor:"2,keyasint,omitempty"`
}

func (c Connection) IsZero() bool { return c == Connection{} }

// Counts are statistics about a particular connection.
type Counts struct {
	TxPackets uint64 `json:"txPkts,omitzero,omitempty"  cbor:"12,keyasint,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitzero,omitempty" cbor:"13,keyasint,omitempty"`
	RxPackets uint64 `json:"rxPkts,omitzero,omitempty"  cbor:"14,keyasint,omitempty"`
	RxBytes   uint64 `json:"rxBytes,omitzero,omitempty" cbor:"15,keyasint,omitempty"`
}

func (c Counts) IsZero() bool { return c == Counts{} }

// Add adds the counts from both c1 and c2.
func (c1 Counts) Add(c2 Counts) Counts {
	c1.TxPackets += c2.TxPackets
	c1.TxBytes += c2.TxBytes
	c1.RxPackets += c2.RxPackets
	c1.RxBytes += c2.RxBytes
	return c1
}
