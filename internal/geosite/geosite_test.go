package geosite

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The encoders below build a minimal dlc.dat-compatible protobuf binary
// for testing the index without needing a real file.

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

// fullParse decodes the whole GeoSiteList, the reference the index is
// checked against.
func fullParse(t *testing.T, data []byte) []Category {
	t.Helper()
	var cats []Category
	for len(data) > 0 {
		fieldNum, wireType, n, err := readTag(data)
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
		if fieldNum == 1 && wireType == 2 {
			payload, n, err := readBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			data = data[n:]
			c, err := parseGeoSite(payload)
			if err != nil {
				t.Fatal(err)
			}
			cats = append(cats, c)
			continue
		}
		n, err = skipField(data, wireType)
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
	return cats
}

// buildDomainWithAttr adds an attribute submessage, which the index and the
// decoder must skip.
func buildDomainWithAttr(domType DomainType, value, attr string) []byte {
	msg := buildDomain(domType, value)
	return append(msg, encodeLenDelim(3, encodeLenDelim(1, []byte(attr)))...)
}

func sample() []byte {
	return buildGeoSiteList(
		buildGeoSite("NETFLIX",
			buildDomain(DomainRoot, "netflix.com"),
			buildDomain(DomainFull, "fast.com"),
			buildDomain(DomainPlain, "nflx"),
			buildDomainWithAttr(DomainRegex, `^nflx\d+\.net$`, "cn"),
		),
		buildGeoSite("GOOGLE",
			buildDomain(DomainRoot, "google.com"),
			buildDomain(DomainRoot, "youtube.com"),
		),
		buildGeoSite("AMAZON",
			buildDomain(DomainRoot, "amazon.com"),
		),
	)
}

func writeDat(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIndexCategoriesMatchFullParse(t *testing.T) {
	data := sample()
	path := filepath.Join(t.TempDir(), "dlc.dat")
	writeDat(t, path, data)
	x := NewIndex(path, nil)

	got, err := x.Categories()
	if err != nil {
		t.Fatal(err)
	}
	var want []CategoryInfo
	for _, c := range fullParse(t, data) {
		want = append(want, CategoryInfo{Name: c.Code, DomainCount: len(c.Domains)})
	}
	slices.SortFunc(want, func(a, b CategoryInfo) int { return strings.Compare(a.Name, b.Name) })
	if !slices.Equal(got, want) {
		t.Fatalf("categories = %+v, want %+v", got, want)
	}
	fi := x.FileInfo()
	if !fi.Downloaded || fi.CategoryCount != 3 || fi.LastModified.IsZero() {
		t.Fatalf("file info = %+v", fi)
	}
}

func TestIndexEntriesDecodesOneCategory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dlc.dat")
	writeDat(t, path, sample())
	x := NewIndex(path, nil)

	want := []string{"domain:netflix.com", "full:fast.com", "keyword:nflx", `regexp:^nflx\d+\.net$`}
	for _, name := range []string{"netflix", "NETFLIX", "NetFlix"} {
		got, ok := x.Entries(name)
		if !ok || !slices.Equal(got, want) {
			t.Fatalf("Entries(%q) = %v, %v; want %v", name, got, ok, want)
		}
	}
	if got, ok := x.Entries("amazon"); !ok || !slices.Equal(got, []string{"domain:amazon.com"}) {
		t.Fatalf("amazon = %v, %v", got, ok)
	}
	if got, ok := x.Entries("nonexistent"); ok || got != nil {
		t.Fatalf("unknown category = %v, %v", got, ok)
	}
}

func TestIndexMissingFile(t *testing.T) {
	x := NewIndex(filepath.Join(t.TempDir(), "dlc.dat"), nil)
	if fi := x.FileInfo(); fi.Downloaded || fi.CategoryCount != 0 {
		t.Fatalf("file info = %+v", fi)
	}
	if cats, err := x.Categories(); err != nil || len(cats) != 0 {
		t.Fatalf("categories = %v, %v", cats, err)
	}
	if _, ok := x.Entries("netflix"); ok {
		t.Fatal("entries from a missing file")
	}
}

func TestIndexCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dlc.dat")
	data := sample()
	writeDat(t, path, data[:len(data)-3])
	x := NewIndex(path, nil)
	if _, err := x.Categories(); err == nil {
		t.Fatal("truncated file indexed without error")
	}
	if _, ok := x.Entries("amazon"); ok {
		t.Fatal("entries from a corrupt file")
	}
	if fi := x.FileInfo(); !fi.Downloaded || fi.CategoryCount != 0 {
		t.Fatalf("file info = %+v", fi)
	}
}

func TestIndexReindexesWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dlc.dat")
	writeDat(t, path, sample())
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	x := NewIndex(path, nil)
	if got, _ := x.Entries("google"); len(got) != 2 {
		t.Fatalf("google = %v", got)
	}

	// Replace the file the way Download does: write a temp file, rename.
	tmp := path + ".tmp"
	writeDat(t, tmp, buildGeoSiteList(
		buildGeoSite("GOOGLE", buildDomain(DomainRoot, "google.com")),
		buildGeoSite("DUCKDUCKGO", buildDomain(DomainRoot, "duckduckgo.com")),
	))
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if got, ok := x.Entries("google"); !ok || !slices.Equal(got, []string{"domain:google.com"}) {
		t.Fatalf("google after update = %v, %v", got, ok)
	}
	if _, ok := x.Entries("netflix"); ok {
		t.Fatal("netflix survived the update")
	}
	if _, ok := x.Entries("duckduckgo"); !ok {
		t.Fatal("new category not found")
	}
	if fi := x.FileInfo(); fi.CategoryCount != 2 {
		t.Fatalf("file info = %+v", fi)
	}

	// Removing the file is "not downloaded".
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if fi := x.FileInfo(); fi.Downloaded {
		t.Fatalf("file info after remove = %+v", fi)
	}
	if _, ok := x.Entries("google"); ok {
		t.Fatal("entries after remove")
	}
}

// Indexing allocates per category, never per domain: a category with 5000
// domains costs the same as one with 5.
func TestIndexNoPerDomainAllocations(t *testing.T) {
	build := func(n int) []byte {
		var ds [][]byte
		for i := 0; i < n; i++ {
			ds = append(ds, buildDomain(DomainRoot, fmt.Sprintf("d%d.example.com", i)))
		}
		return buildGeoSiteList(buildGeoSite("A", ds...), buildGeoSite("B", ds...))
	}
	allocs := func(data []byte) float64 {
		return testing.AllocsPerRun(20, func() {
			if _, _, _, err := scanIndex(bytes.NewReader(data), int64(len(data))); err != nil {
				t.Fatal(err)
			}
		})
	}
	small, large := allocs(build(5)), allocs(build(5000))
	if large > small {
		t.Fatalf("allocs: %v for 5 domains per category, %v for 5000", small, large)
	}
	if large > 20 {
		t.Fatalf("allocs = %v for two categories", large)
	}
}

func TestIndexEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dlc.dat")
	writeDat(t, path, nil)
	x := NewIndex(path, nil)
	cats, err := x.Categories()
	if err != nil || len(cats) != 0 {
		t.Fatalf("categories = %v, %v", cats, err)
	}
	if fi := x.FileInfo(); !fi.Downloaded {
		t.Fatalf("file info = %+v", fi)
	}
}
