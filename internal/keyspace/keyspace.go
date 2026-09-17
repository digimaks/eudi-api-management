// Package keyspace is the one place a deployment-configured key prefix is
// applied. The key names each store uses (vc:handoff:…, vc:respcode:…,
// mgmt:webhook:…) are the contract shared with the other services and never
// change; the prefix is an environment fact — a managed Redis commonly
// confines a user's ACL to one key pattern, where an unprefixed write is
// refused — laid in front of them. Every service that shares the cache must
// be configured with the same prefix, or the readers see an empty cache.
package keyspace

import "strings"

// Prefix is the normalized "<prefix>:" (or "" for none).
type Prefix string

// New normalizes a configured prefix: trims whitespace and any trailing ":",
// then appends exactly one ":". Empty stays empty.
func New(p string) Prefix {
	p = strings.TrimRight(strings.TrimSpace(p), ":")
	if p == "" {
		return ""
	}
	return Prefix(p + ":")
}

// Key applies the prefix to a contract key.
func (p Prefix) Key(k string) string { return string(p) + k }
