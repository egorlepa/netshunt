//go:build mage

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	version    = "0.8.13"
	binaryName = "kst"
	ldflags    = fmt.Sprintf("-s -w -X main.version=%s", version)
)

// Build builds the binary for the host platform.
func Build() error {
	if err := generate(); err != nil {
		return err
	}
	fmt.Println("Building for host platform...")
	return goBuild("", "", "")
}

// BuildRouter cross-compiles for aarch64 (Keenetic Giga KN-1012).
func BuildRouter() error {
	if err := generate(); err != nil {
		return err
	}
	fmt.Println("Cross-compiling for linux/arm64...")
	return goBuild("linux", "arm64", "aarch64")
}

// Package builds the aarch64 binary and creates an IPK package.
func Package() error {
	if err := BuildRouter(); err != nil {
		return err
	}
	fmt.Println("Creating IPK package...")
	return buildIPK()
}

// Test runs all tests.
func Test() error {
	return sh("go", "test", "./...")
}

// Lint runs golangci-lint.
func Lint() error {
	return sh("golangci-lint", "run", "./...")
}

// Clean removes build artifacts.
func Clean() error {
	return os.RemoveAll("dist")
}

func generate() error {
	fmt.Println("Running go generate...")
	return sh("go", "generate", "./...")
}

func goBuild(goos, goarch, suffix string) error {
	output := filepath.Join("dist", binaryName)
	if suffix != "" {
		output = filepath.Join("dist", fmt.Sprintf("%s_%s", binaryName, suffix))
	}

	if err := os.MkdirAll("dist", 0755); err != nil {
		return err
	}

	env := os.Environ()
	env = append(env, "CGO_ENABLED=0")
	if goos != "" {
		env = append(env, "GOOS="+goos)
	}
	if goarch != "" {
		env = append(env, "GOARCH="+goarch)
	}

	cmd := exec.Command("go", "build",
		"-ldflags", ldflags,
		"-trimpath",
		"-o", output,
		"./cmd/kst",
	)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildIPK() error {
	binary := filepath.Join("dist", "kst_aarch64")
	info, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	now := time.Now()

	// Build data.tar.gz — the filesystem contents.
	dataBuf, installedSize, err := buildDataTar(binary, info, now)
	if err != nil {
		return fmt.Errorf("build data.tar.gz: %w", err)
	}

	// Build control.tar.gz — package metadata.
	controlBuf, err := buildControlTar(installedSize, now)
	if err != nil {
		return fmt.Errorf("build control.tar.gz: %w", err)
	}

	// Assemble the IPK (outer tar.gz with debian-binary + control.tar.gz + data.tar.gz).
	ipkPath := filepath.Join("dist", fmt.Sprintf("kst_%s_aarch64.ipk", version))
	if err := assembleIPK(ipkPath, controlBuf, dataBuf, now); err != nil {
		return fmt.Errorf("assemble IPK: %w", err)
	}

	ipkInfo, _ := os.Stat(ipkPath)
	fmt.Printf("Package created: %s (%d KB)\n", ipkPath, ipkInfo.Size()/1024)
	return nil
}

func buildDataTar(binaryPath string, binaryInfo os.FileInfo, now time.Time) ([]byte, int64, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	var installedSize int64

	// Helper to add a directory entry.
	addDir := func(name string) error {
		return tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeDir,
			Mode:     0755,
			ModTime:  now,
		})
	}

	// Helper to add a file from disk.
	addFile := func(name, src string, mode int64) error {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		installedSize += int64(len(data))
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Mode:     mode,
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	}

	// Directories.
	for _, d := range []string{
		"./opt/", "./opt/bin/", "./opt/etc/", "./opt/etc/kst/",
		"./opt/etc/kst/ndm/", "./opt/etc/kst/init.d/",
		"./opt/etc/kst/ndm/fs.d/", "./opt/etc/kst/ndm/netfilter.d/",
		"./opt/etc/kst/ndm/ifstatechanged.d/", "./opt/etc/kst/ndm/ifcreated.d/",
		"./opt/etc/kst/ndm/ifdestroyed.d/", "./opt/etc/kst/ndm/wan.d/",
	} {
		if err := addDir(d); err != nil {
			return nil, 0, err
		}
	}

	// Binary.
	binData, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, 0, err
	}
	installedSize += int64(len(binData))
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./opt/bin/kst",
		Size:     int64(len(binData)),
		Mode:     0755,
		ModTime:  now,
		Typeflag: tar.TypeReg,
	}); err != nil {
		return nil, 0, err
	}
	if _, err := tw.Write(binData); err != nil {
		return nil, 0, err
	}

	// NDM scripts.
	ndmScripts := map[string]string{
		"./opt/etc/kst/ndm/fs.d/100-ipset":                 "scripts/ndm/fs.d/100-ipset",
		"./opt/etc/kst/ndm/netfilter.d/100-proxy-redirect": "scripts/ndm/netfilter.d/100-proxy-redirect",
		"./opt/etc/kst/ndm/netfilter.d/100-dns-local":      "scripts/ndm/netfilter.d/100-dns-local",
		"./opt/etc/kst/ndm/ifstatechanged.d/100-unblock":   "scripts/ndm/ifstatechanged.d/100-unblock",
		"./opt/etc/kst/ndm/ifcreated.d/kst-iface-add":      "scripts/ndm/ifcreated.d/kst-iface-add",
		"./opt/etc/kst/ndm/ifdestroyed.d/kst-iface-del":    "scripts/ndm/ifdestroyed.d/kst-iface-del",
		"./opt/etc/kst/ndm/wan.d/internet-up":              "scripts/ndm/wan.d/internet-up",
	}
	for dest, src := range ndmScripts {
		if err := addFile(dest, src, 0755); err != nil {
			return nil, 0, fmt.Errorf("add %s: %w", src, err)
		}
	}

	// Init.d script.
	if err := addFile("./opt/etc/kst/init.d/S96kst", "scripts/init.d/S96kst", 0755); err != nil {
		return nil, 0, err
	}

	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gw.Close(); err != nil {
		return nil, 0, err
	}

	return buf.Bytes(), installedSize, nil
}

func buildControlTar(installedSize int64, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	addControlFile := func(name string, data []byte, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:     "./" + name,
			Size:     int64(len(data)),
			Mode:     mode,
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	// Generate control file from template.
	tmplData, err := os.ReadFile("packaging/ipk/control.tmpl")
	if err != nil {
		return nil, err
	}
	control := strings.ReplaceAll(string(tmplData), "{{.Version}}", version)
	control = strings.ReplaceAll(control, "{{.InstalledSize}}", fmt.Sprintf("%d", installedSize))
	if err := addControlFile("control", []byte(control), 0644); err != nil {
		return nil, err
	}

	// Add lifecycle scripts.
	for _, script := range []string{"postinst", "prerm", "postrm"} {
		data, err := os.ReadFile(filepath.Join("packaging/ipk", script))
		if err != nil {
			return nil, err
		}
		if err := addControlFile(script, data, 0755); err != nil {
			return nil, err
		}
	}

	// Add conffiles.
	conffiles, err := os.ReadFile("packaging/ipk/conffiles")
	if err != nil {
		return nil, err
	}
	if err := addControlFile("conffiles", conffiles, 0644); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func assembleIPK(path string, controlTar, dataTar []byte, now time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	addEntry := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0644,
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	// debian-binary must be first.
	if err := addEntry("debian-binary", []byte("2.0\n")); err != nil {
		return err
	}
	if err := addEntry("control.tar.gz", controlTar); err != nil {
		return err
	}
	if err := addEntry("data.tar.gz", dataTar); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
