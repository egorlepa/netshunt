package routing

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Rule comparison works on a canonical token form, because `iptables -S`
// does not print a rule exactly as it was given:
//
//	given:   -p udp --dport 53 -j REDIRECT --to-port 53
//	printed: -p udp -m udp --dport 53 -j REDIRECT --to-ports 53
//
// canonicalRule maps both to the same string:
//   - long option names become short ones (--destination -> -d, ...);
//   - the basic matches -s -d -i -o -p (with an optional "!") move to the
//     front in that order, which is the order iptables prints them in;
//     everything else keeps its relative order;
//   - the implicit "-m tcp"/"-m udp" that iptables adds for --dport/--sport
//     is dropped when it repeats the -p protocol;
//   - --to-port becomes --to-ports, --destination-port becomes --dport;
//   - addresses become masked CIDRs (1.2.3.4 -> 1.2.3.4/32,
//     10.1.0.0/255.0.0.0 -> 10.0.0.0/8);
//   - TPROXY's default "--on-ip 0.0.0.0" is dropped, a bare --tproxy-mark
//     value gets the default /0xffffffff mask.

// optGroup is one option with its values, e.g. ["-d", "10.0.0.0/8"], with
// neg set for a preceding "!".
type optGroup struct {
	neg  bool
	opt  string
	vals []string
}

var longOpts = map[string]string{
	"--source":           "-s",
	"--src":              "-s",
	"--destination":      "-d",
	"--dst":              "-d",
	"--in-interface":     "-i",
	"--out-interface":    "-o",
	"--protocol":         "-p",
	"--jump":             "-j",
	"--goto":             "-g",
	"--match":            "-m",
	"--to-port":          "--to-ports",
	"--destination-port": "--dport",
	"--source-port":      "--sport",
}

var basicOrder = map[string]int{"-s": 0, "-d": 1, "-i": 2, "-o": 3, "-p": 4}

func groupTokens(tokens []string) []optGroup {
	var groups []optGroup
	neg := false
	for _, t := range tokens {
		switch {
		case t == "!":
			neg = true
		case strings.HasPrefix(t, "-") && len(t) > 1 && !isNumber(t):
			if o, ok := longOpts[t]; ok {
				t = o
			}
			groups = append(groups, optGroup{neg: neg, opt: t})
			neg = false
		default:
			if len(groups) == 0 {
				groups = append(groups, optGroup{})
			}
			g := &groups[len(groups)-1]
			g.vals = append(g.vals, t)
		}
	}
	return groups
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func canonicalAddr(v string) string {
	if strings.Contains(v, "/") {
		addr, mask, _ := strings.Cut(v, "/")
		if m, err := netip.ParseAddr(mask); err == nil && m.Is4() {
			b := m.As4()
			bits := 0
			for _, x := range b {
				for i := 7; i >= 0; i-- {
					if x&(1<<i) != 0 {
						bits++
					}
				}
			}
			v = addr + "/" + strconv.Itoa(bits)
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			return p.Masked().String()
		}
		return v
	}
	if a, err := netip.ParseAddr(v); err == nil && a.Is4() {
		return a.String() + "/32"
	}
	return v
}

// canonicalRule returns the comparison key of a rule spec (the tokens after
// "-A <chain>").
func canonicalRule(tokens []string) string {
	groups := groupTokens(tokens)

	proto := ""
	for _, g := range groups {
		if g.opt == "-p" && len(g.vals) > 0 && !g.neg {
			proto = strings.ToLower(g.vals[0])
		}
	}

	var basic, rest []optGroup
	for i := 0; i < len(groups); i++ {
		g := groups[i]
		switch g.opt {
		case "-s", "-d":
			for j := range g.vals {
				g.vals[j] = canonicalAddr(g.vals[j])
			}
		case "-p":
			for j := range g.vals {
				g.vals[j] = strings.ToLower(g.vals[j])
			}
		case "-m":
			if len(g.vals) == 1 && proto != "" && g.vals[0] == proto {
				continue // implicit protocol match iptables prints
			}
		case "--on-ip":
			if len(g.vals) == 1 && g.vals[0] == "0.0.0.0" {
				continue
			}
		case "--tproxy-mark":
			if len(g.vals) == 1 && !strings.Contains(g.vals[0], "/") {
				g.vals[0] += "/0xffffffff"
			}
		}
		if _, ok := basicOrder[g.opt]; ok {
			basic = append(basic, g)
		} else {
			rest = append(rest, g)
		}
	}
	slices.SortStableFunc(basic, func(a, b optGroup) int { return basicOrder[a.opt] - basicOrder[b.opt] })

	var out []string
	for _, g := range append(basic, rest...) {
		if g.neg {
			out = append(out, "!")
		}
		if g.opt != "" {
			out = append(out, g.opt)
		}
		out = append(out, g.vals...)
	}
	return strings.Join(out, " ")
}

// savedRule is one "-A <chain> ..." line of `iptables -S` output.
type savedRule struct {
	spec []string // tokens after "-A <chain>", valid input for -D
	key  string   // canonicalRule(spec)
}

// parseSave extracts the rules of chain from `iptables -S <chain>` output.
// "-N"/"-P" lines and rules of other chains are ignored.
func parseSave(out, chain string) []savedRule {
	var rules []savedRule
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || f[1] != chain {
			continue
		}
		spec := f[2:]
		rules = append(rules, savedRule{spec: spec, key: canonicalRule(spec)})
	}
	return rules
}
