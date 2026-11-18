// Linux entry point for the single-file VPN Dock build.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

//go:embed payload.tar.gz
var payload []byte

var payloadHash string
var bundledEngine string

const maxPayloadSize = 512 << 20
const noExecFilesystem = 8 // Linux ST_NOEXEC.

func main() {
	// Linux attaches the child-death signal to this thread, rather than to
	// the whole Go process. Keep the thread alive until the GUI exits.
	runtime.LockOSThread()
	code := launch()
	runtime.UnlockOSThread()
	os.Exit(code)
}

func launch() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != payloadHash {
		return report("The executable's contents failed verification. Download a fresh copy.")
	}
	directory, err := privateDirectory(bundledEngine == "yes")
	if err != nil {
		return report(err.Error())
	}
	defer os.RemoveAll(directory)

	if err := unpack(ctx, directory); err != nil {
		return report("Could not unpack VPN Dock: " + err.Error())
	}
	if len(os.Args) == 2 && os.Args[1] == "--portable-notices" {
		return printNotices(directory)
	}

	python := "/usr/bin/python3"
	if info, err := os.Stat(python); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		python, err = exec.LookPath("python3")
		if err != nil {
			return report("Python 3 is required. Install your distribution's Python, GTK 4, PyGObject and libadwaita packages.")
		}
	}

	args := append([]string{"-E", "-s", "-B", "-m", "vpngate"}, os.Args[1:]...)
	command := exec.CommandContext(ctx, python, args...)
	command.Dir = directory
	launcherDir := ""
	if executable, err := os.Executable(); err == nil {
		launcherDir = filepath.Dir(executable)
	}
	command.Env = append(command.Environ(), "VPNDOCK_PORTABLE=1", "VPNDOCK_LAUNCHER_DIR="+launcherDir)
	if bundledEngine == "yes" {
		command.Env = append(command.Env, "VPNDOCK_SING_BOX="+filepath.Join(directory, "engine", "sing-box"))
	}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 8 * time.Second
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if wait, ok := exit.Sys().(syscall.WaitStatus); ok && wait.Signaled() {
				return 128 + int(wait.Signal())
			}
			return exit.ExitCode()
		}
		if ctx.Err() != nil {
			return 1
		}
		return report("Could not start VPN Dock: " + err.Error())
	}
	return 0
}

func privateDirectory(needsExecution bool) (string, error) {
	for _, base := range []string{os.Getenv("XDG_RUNTIME_DIR"), os.TempDir(), "/tmp"} {
		if !filepath.IsAbs(base) {
			continue
		}
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int(owner.Uid) != os.Getuid() && info.Mode()&os.ModeSticky == 0) ||
			(info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			continue
		}
		if needsExecution {
			var stat syscall.Statfs_t
			if err := syscall.Statfs(base, &stat); err != nil || stat.Flags&noExecFilesystem != 0 {
				continue
			}
		}
		if directory, err := os.MkdirTemp(base, "vpngate-portable-"); err == nil {
			return directory, nil
		}
	}
	return "", errors.New("VPN Dock could not create a private, executable temporary directory")
}

func unpack(ctx context.Context, directory string) error {
	compressed, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	size := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		member, err := archive.Next()
		if errors.Is(err, io.EOF) {
			// Read through the gzip trailer so its checksum is also verified.
			_, err := io.Copy(io.Discard, compressed)
			return err
		}
		if err != nil {
			return err
		}
		if !validMember(member) || member.Size > maxPayloadSize-size {
			return errors.New("invalid entry in the embedded archive")
		}
		size += member.Size
		if err := extractMember(archive, member, directory); err != nil {
			return err
		}
	}
}

func validMember(member *tar.Header) bool {
	if member.Typeflag != tar.TypeReg || member.Size < 0 || !fs.ValidPath(member.Name) {
		return false
	}
	if prefix, name, ok := strings.Cut(member.Name, "/"); ok && prefix == "vpngate" && !strings.Contains(name, "/") {
		return strings.HasSuffix(name, ".py") || name == "style.css" || name == "vpndock.png"
	}
	switch member.Name {
	case "LICENSE", "THIRD-PARTY-NOTICES":
		return true
	case "engine/sing-box", "engine/LICENSE", "engine/SOURCE":
		return bundledEngine == "yes"
	default:
		return false
	}
}

func extractMember(archive io.Reader, member *tar.Header, directory string) error {
	destination := filepath.Join(directory, filepath.FromSlash(member.Name))
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	mode := fs.FileMode(0600)
	if member.Name == "engine/sing-box" {
		mode = 0700
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, archive)
	closeErr := file.Close()
	return errors.Join(copyErr, closeErr)
}

func printNotices(directory string) int {
	names := []string{"LICENSE", "THIRD-PARTY-NOTICES"}
	if bundledEngine == "yes" {
		names = append(names, "engine/SOURCE", "engine/LICENSE")
	}
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return report(err.Error())
		}
		fmt.Print(string(content))
		fmt.Println()
	}
	return 0
}

func report(message string) int {
	fmt.Fprintln(os.Stderr, "VPN Dock:", message)
	if len(os.Args) == 1 && (os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != "") {
		if dialog, err := exec.LookPath("zenity"); err == nil {
			_ = exec.Command(dialog, "--error", "--title=VPN Dock", "--no-markup", "--text="+message).Run()
		} else if dialog, err := exec.LookPath("kdialog"); err == nil {
			_ = exec.Command(dialog, "--title", "VPN Dock", "--error", message).Run()
		}
	}
	return 1
}
