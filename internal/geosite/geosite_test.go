package geosite

import (
	"encoding/binary"
	"testing"
)

// buildProtobuf constructs a minimal dlc.dat-compatible protobuf binary
// for testing the parser without needing a real file.

func encodeVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

func encodeTag(fieldNum, wireType int) []byte {
	return encodeVarint(uint64(fieldNum<<3 | wireType))
}

func encodeLenDelim(fieldNum int, data []byte) []byte {
	var out []byte
	out = append(out, encodeTag(fieldNum, 2)...)
	out = append(out, encodeVarint(uint64(len(data)))...)
	out = append(out, data...)
	return out
}

func encodeVarintField(fieldNum int, v uint64) []byte {
	var out []byte
	out = append(out, encodeTag(fieldNum, 0)...)
	out = append(out, encodeVarint(v)...)
	return out
}

func buildDomain(domType DomainType, value string) []byte {
	var msg []byte
	if domType != 0 {
		msg = append(msg, encodeVarintField(1, uint64(domType))...)
	}
	msg = append(msg, encodeLenDelim(2, []byte(value))...)
	return msg
}

func buildGeoSite(code string, domains ...[]byte) []byte {
	var msg []byte
	msg = append(msg, encodeLenDelim(1, []byte(code))...)
	for _, d := range domains {
		msg = append(msg, encodeLenDelim(2, d)...)
	}
	return msg
}

func buildGeoSiteList(sites ...[]byte) []byte {
	var data []byte
	for _, s := range sites {
		data = append(data, encodeLenDelim(1, s)...)
	}
	return data
}

func TestParseGeoSiteList(t *testing.T) {
	data := buildGeoSiteList(
		buildGeoSite("NETFLIX",
			buildDomain(DomainRoot, "netflix.com"),
			buildDomain(DomainFull, "fast.com"),
			buildDomain(DomainPlain, "nflx"),    // keyword, should be filtered
			buildDomain(DomainRegex, "nflx.*"),   // regex, should be filtered
		),
		buildGeoSite("GOOGLE",
			buildDomain(DomainRoot, "google.com"),
			buildDomain(DomainRoot, "youtube.com"),
		),
	)

	db, err := parseGeoSiteList(data)
	if err != nil {
		t.Fatalf("parseGeoSiteList: %v", err)
	}
	if len(db.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(db.Categories))
	}

	// Check NETFLIX.
	netflix := db.Categories[0]
	if netflix.Code != "NETFLIX" {
		t.Errorf("expected NETFLIX, got %q", netflix.Code)
	}
	if len(netflix.Domains) != 4 {
		t.Errorf("expected 4 domains in NETFLIX, got %d", len(netflix.Domains))
	}

	// Check GOOGLE.
	google := db.Categories[1]
	if google.Code != "GOOGLE" {
		t.Errorf("expected GOOGLE, got %q", google.Code)
	}
	if len(google.Domains) != 2 {
		t.Errorf("expected 2 domains in GOOGLE, got %d", len(google.Domains))
	}
}

func TestExtractDomains(t *testing.T) {
	data := buildGeoSiteList(
		buildGeoSite("NETFLIX",
			buildDomain(DomainRoot, "netflix.com"),
			buildDomain(DomainFull, "fast.com"),
			buildDomain(DomainPlain, "nflx"),
			buildDomain(DomainRegex, "nflx.*"),
		),
	)

	db, err := parseGeoSiteList(data)
	if err != nil {
		t.Fatalf("parseGeoSiteList: %v", err)
	}

	// Only RootDomain and Full should be extracted.
	domains, err := ExtractDomains(db, "netflix")
	if err != nil {
		t.Fatalf("ExtractDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d: %v", len(domains), domains)
	}
	if domains[0] != "netflix.com" || domains[1] != "fast.com" {
		t.Errorf("unexpected domains: %v", domains)
	}

	// Case-insensitive lookup.
	domains, err = ExtractDomains(db, "NETFLIX")
	if err != nil {
		t.Fatalf("case-insensitive lookup: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	// Missing category.
	_, err = ExtractDomains(db, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent category")
	}
}

func TestListCategories(t *testing.T) {
	data := buildGeoSiteList(
		buildGeoSite("GOOGLE",
			buildDomain(DomainRoot, "google.com"),
		),
		buildGeoSite("AMAZON",
			buildDomain(DomainRoot, "amazon.com"),
			buildDomain(DomainRoot, "aws.com"),
		),
	)

	db, err := parseGeoSiteList(data)
	if err != nil {
		t.Fatalf("parseGeoSiteList: %v", err)
	}

	infos := ListCategories(db)
	if len(infos) != 2 {
		t.Fatalf("expected 2, got %d", len(infos))
	}

	// Should be sorted alphabetically.
	if infos[0].Name != "AMAZON" {
		t.Errorf("expected AMAZON first, got %q", infos[0].Name)
	}
	if infos[0].DomainCount != 2 {
		t.Errorf("expected 2 domains for AMAZON, got %d", infos[0].DomainCount)
	}
	if infos[1].Name != "GOOGLE" {
		t.Errorf("expected GOOGLE second, got %q", infos[1].Name)
	}
}

func TestEmptyDatabase(t *testing.T) {
	db, err := parseGeoSiteList(nil)
	if err != nil {
		t.Fatalf("parseGeoSiteList(nil): %v", err)
	}
	if len(db.Categories) != 0 {
		t.Errorf("expected 0 categories, got %d", len(db.Categories))
	}

	infos := ListCategories(db)
	if len(infos) != 0 {
		t.Errorf("expected 0 infos, got %d", len(infos))
	}
}
