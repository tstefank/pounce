package triggers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Profile is the learned per-(server, tool) network baseline that feeds the
// novelty trigger (#4) and the learned half of capability mismatch (#1). It
// persists across sessions at ~/.pounce/profile.json.
//
// Order-independent by construction: every fact stores the *earliest session
// id* that established it, and all queries take the id of the session being
// evaluated ("as of") and compare against strictly-earlier sessions. So
// learning the session you are about to view never suppresses that session's
// own debut destinations — only genuinely-prior sessions form the baseline.
//
// The seen-domain set is a mute/acknowledge list, not an allow-list (TRIGGERS.md
// invariant): it suppresses repeat notifications, it never permits traffic.
type Profile struct {
	mu      sync.Mutex
	path    string
	Tools   map[string]*toolStat `json:"tools"`
	Learned map[string]bool      `json:"learned_sessions"`
}

// toolStat is the baseline for one (server, tool). Stored ids are the earliest
// (by timestamp prefix, see idOrder) session that established each fact.
type toolStat struct {
	First   string            `json:"first,omitempty"`   // earliest session that observed this (S,T)
	Egress  string            `json:"egress,omitempty"`  // earliest session in which it egressed ("" = never)
	Domains map[string]string `json:"domains,omitempty"` // registrable domain → earliest session seen
}

func profileKey(server, tool string) string { return server + "\x00" + tool }

// idOrder returns the chronologically-comparable part of a session id. Ids are
// "<date>-<time>-<pid>" (store.NewID); the "-<pid>" suffix is variable-width and
// carries no chronological meaning, so ordering uses only the timestamp prefix
// (everything before the last "-"). Ids sharing a prefix are "concurrent" —
// neither earlier — the safe direction, since a concurrent sibling's
// destinations are then not suppressed as already-seen.
func idOrder(id string) string {
	if i := strings.LastIndexByte(id, '-'); i >= 0 {
		return id[:i]
	}
	return id
}

// earlier reports whether session id a is strictly earlier than b by timestamp
// prefix. An empty a is "no such session".
func earlier(a, b string) bool { return a != "" && idOrder(a) < idOrder(b) }

// minID returns the earlier of two session ids by timestamp prefix, ignoring
// empties. It keeps a full id (used as Learned-set identity elsewhere).
func minID(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case idOrder(a) <= idOrder(b):
		return a
	default:
		return b
	}
}

// NewProfile returns an empty in-memory profile with no backing file (Save will
// error until a path is set via LoadProfile). Useful for transient evaluation
// and tests.
func NewProfile() *Profile {
	return &Profile{Tools: map[string]*toolStat{}, Learned: map[string]bool{}}
}

// ProfilePath is ~/.pounce/profile.json.
func ProfilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".pounce", "profile.json"), nil
}

// LoadProfile reads the saved profile, returning an empty (usable) one if none
// exists yet. A malformed file yields an empty profile rather than an error, so
// a corrupt baseline never blocks evaluation.
func LoadProfile() (*Profile, error) {
	path, err := ProfilePath()
	if err != nil {
		return nil, err
	}
	p := &Profile{path: path, Tools: map[string]*toolStat{}, Learned: map[string]bool{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("read profile: %w", err)
	}
	_ = json.Unmarshal(data, p) // tolerate a corrupt file: keep the empty maps
	if p.Tools == nil {
		p.Tools = map[string]*toolStat{}
	}
	if p.Learned == nil {
		p.Learned = map[string]bool{}
	}
	return p, nil
}

// Known reports whether domain was already seen for this (S,T) in a session
// earlier than asOf — i.e. it is not novel for the session being evaluated.
func (p *Profile) Known(server, tool, domain, asOf string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ts := p.Tools[profileKey(server, tool)]
	return ts != nil && earlier(ts.Domains[domain], asOf)
}

// Cold reports whether this (S,T) is still in its learning window as of asOf:
// no session earlier than asOf has observed it (the chosen policy is a
// one-session window). Novelty findings are softened while cold.
func (p *Profile) Cold(server, tool, asOf string) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ts := p.Tools[profileKey(server, tool)]
	return ts == nil || !earlier(ts.First, asOf)
}

// NeverEgressed reports the learned half of capability mismatch: this (S,T) was
// observed in an earlier session but has never egressed in any session before
// asOf — so a connection now is anomalous even though the built-in prior missed
// it. Returns false for a tool with no prior baseline (cold start has no signal).
func (p *Profile) NeverEgressed(server, tool, asOf string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ts := p.Tools[profileKey(server, tool)]
	return ts != nil && earlier(ts.First, asOf) && !earlier(ts.Egress, asOf)
}

// Learn folds a session's report into the baseline, keyed by sessionID. It is
// idempotent (re-learning the same session is a no-op) and order-independent
// (every fact keeps the earliest session id). Returns true if it changed state.
func (p *Profile) Learn(sessionID string, rep Report) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if sessionID == "" || p.Learned[sessionID] {
		return false
	}
	p.Learned[sessionID] = true
	for _, cf := range rep.Calls {
		if cf.Tool == "" {
			continue
		}
		k := profileKey(rep.Server, cf.Tool)
		ts := p.Tools[k]
		if ts == nil {
			ts = &toolStat{Domains: map[string]string{}}
			p.Tools[k] = ts
		}
		if ts.Domains == nil {
			ts.Domains = map[string]string{}
		}
		ts.First = minID(ts.First, sessionID)
		for _, f := range cf.Findings {
			if !isPrivate(ipOf(f.Conn.Remote())) {
				ts.Egress = minID(ts.Egress, sessionID)
			}
			if f.Domain != "" {
				ts.Domains[f.Domain] = minID(ts.Domains[f.Domain], sessionID)
			}
		}
	}
	return true
}

// Save atomically writes the profile to disk (temp file + rename), creating
// ~/.pounce if needed.
func (p *Profile) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == "" {
		return errors.New("profile has no path")
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return fmt.Errorf("create profile dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode profile: %w", err)
	}
	// Write to a per-process unique temp, then rename. A shared fixed temp name
	// would let concurrent writers (parallel `pounce wrap` closes) tear each
	// other's file — and a torn profile.json is silently reset to empty on the
	// next load, wiping the whole baseline. CreateTemp gives a unique name.
	tmp, err := os.CreateTemp(filepath.Dir(p.path), "profile-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp profile: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("write profile: %w", err)
	}
	if err := os.Rename(tmpName, p.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replace profile: %w", err)
	}
	return nil
}
