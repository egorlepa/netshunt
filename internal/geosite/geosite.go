package geosite

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DownloadURL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

// DomainType matches v2fly protobuf Domain.Type enum.
type DomainType int

const (
	DomainPlain  DomainType = 0 // keyword match
	DomainRegex  DomainType = 1 // regex
	DomainRoot   DomainType = 2 // domain and all subdomains
	DomainFull   DomainType = 3 // exact match
)

// Domain is a single entry in a geosite category.
type Domain struct {
	Type  DomainType
	Value string
}

// Category is a named collection of domains (e.g. "google", "netflix").
type Category struct {
	Code    string
	Domains []Domain
}

// CategoryInfo is a summary of a category for listing purposes.
type CategoryInfo struct {
	Name        string
	DomainCount int
}

// Database holds all parsed geosite categories.
type Database struct {
	Categories []Category
}

// FileInfo holds metadata about the downloaded database file.
type FileInfo struct {
	Downloaded    bool
	LastModified  time.Time
	CategoryCount int
}

// Download fetches dlc.dat from GitHub and writes it to destPath.
func Download(ctx context.Context, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmp := destPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(tmp)
	}()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return os.Rename(tmp, destPath)
}

// Parse reads a dlc.dat file and returns the parsed database.
func Parse(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geosite file: %w", err)
	}
	return parseGeoSiteList(data)
}

// ListCategories returns sorted category summaries from a parsed database.
func ListCategories(db *Database) []CategoryInfo {
	infos := make([]CategoryInfo, len(db.Categories))
	for i, c := range db.Categories {
		infos[i] = CategoryInfo{
			Name:        c.Code,
			DomainCount: len(c.Domains),
		}
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})
	return infos
}

// ExtractDomains returns domain strings for a category, filtered to only
// RootDomain and Full types (the types netshunt can use).
func ExtractDomains(db *Database, category string) ([]string, error) {
	category = strings.ToLower(category)
	for _, c := range db.Categories {
		if strings.ToLower(c.Code) != category {
			continue
		}
		var domains []string
		for _, d := range c.Domains {
			if d.Type == DomainRoot || d.Type == DomainFull {
				domains = append(domains, d.Value)
			}
		}
		return domains, nil
	}
	return nil, fmt.Errorf("category %q not found", category)
}

// Protobuf wire format decoder for the v2fly geosite format.
//
// Wire format:
//   GeoSiteList { repeated GeoSite entry = 1; }
//   GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//   Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//
// Wire types: 0 = varint, 2 = length-delimited (string, bytes, embedded message)

func parseGeoSiteList(data []byte) (*Database, error) {
	db := &Database{}
	for len(data) > 0 {
		fieldNum, wireType, n, err := readTag(data)
		if err != nil {
			return nil, fmt.Errorf("read GeoSiteList tag: %w", err)
		}
		data = data[n:]

		if wireType == 2 && fieldNum == 1 {
			payload, n, err := readBytes(data)
			if err != nil {
				return nil, fmt.Errorf("read GeoSite payload: %w", err)
			}
			data = data[n:]

			cat, err := parseGeoSite(payload)
			if err != nil {
				return nil, fmt.Errorf("parse GeoSite: %w", err)
			}
			db.Categories = append(db.Categories, cat)
		} else {
			n, err := skipField(data, wireType)
			if err != nil {
				return nil, fmt.Errorf("skip GeoSiteList field: %w", err)
			}
			data = data[n:]
		}
	}
	return db, nil
}

func parseGeoSite(data []byte) (Category, error) {
	var cat Category
	for len(data) > 0 {
		fieldNum, wireType, n, err := readTag(data)
		if err != nil {
			return cat, err
		}
		data = data[n:]

		switch {
		case fieldNum == 1 && wireType == 2: // country_code
			payload, n, err := readBytes(data)
			if err != nil {
				return cat, err
			}
			data = data[n:]
			cat.Code = string(payload)

		case fieldNum == 2 && wireType == 2: // domain
			payload, n, err := readBytes(data)
			if err != nil {
				return cat, err
			}
			data = data[n:]
			d, err := parseDomain(payload)
			if err != nil {
				return cat, err
			}
			cat.Domains = append(cat.Domains, d)

		default:
			n, err := skipField(data, wireType)
			if err != nil {
				return cat, err
			}
			data = data[n:]
		}
	}
	return cat, nil
}

func parseDomain(data []byte) (Domain, error) {
	var d Domain
	for len(data) > 0 {
		fieldNum, wireType, n, err := readTag(data)
		if err != nil {
			return d, err
		}
		data = data[n:]

		switch {
		case fieldNum == 1 && wireType == 0: // type (varint)
			v, n, err := readVarint(data)
			if err != nil {
				return d, err
			}
			data = data[n:]
			d.Type = DomainType(v)

		case fieldNum == 2 && wireType == 2: // value (string)
			payload, n, err := readBytes(data)
			if err != nil {
				return d, err
			}
			data = data[n:]
			d.Value = string(payload)

		default: // skip attributes and unknown fields
			n, err := skipField(data, wireType)
			if err != nil {
				return d, err
			}
			data = data[n:]
		}
	}
	return d, nil
}

// Low-level protobuf wire format helpers.

func readTag(data []byte) (fieldNum int, wireType int, n int, err error) {
	v, n, err := readVarint(data)
	if err != nil {
		return 0, 0, 0, err
	}
	return int(v >> 3), int(v & 0x7), n, nil
}

func readVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("unexpected end of data")
	}
	v, n := binary.Uvarint(data)
	if n <= 0 {
		return 0, 0, fmt.Errorf("invalid varint")
	}
	return v, n, nil
}

func readBytes(data []byte) ([]byte, int, error) {
	length, n, err := readVarint(data)
	if err != nil {
		return nil, 0, err
	}
	total := n + int(length)
	if total > len(data) {
		return nil, 0, fmt.Errorf("length-delimited field exceeds data")
	}
	return data[n:total], total, nil
}

func skipField(data []byte, wireType int) (int, error) {
	switch wireType {
	case 0: // varint
		_, n, err := readVarint(data)
		return n, err
	case 1: // 64-bit
		if len(data) < 8 {
			return 0, fmt.Errorf("unexpected end for 64-bit field")
		}
		return 8, nil
	case 2: // length-delimited
		_, n, err := readBytes(data)
		return n, err
	case 5: // 32-bit
		if len(data) < 4 {
			return 0, fmt.Errorf("unexpected end for 32-bit field")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unknown wire type %d", wireType)
	}
}
