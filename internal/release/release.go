// Package release fetches and verifies a Holistic release.
//
// The installer already does this in shell, and this is deliberately the same
// chain rather than a second opinion about it: fetch the manifest, check its
// Ed25519 signature against the key the build embedded, then check the archive's
// SHA-256 against that manifest, and only then unpack. Two different answers to
// "is this release trustworthy" is one answer too many, so if this ever diverges
// from install.sh, that is the bug.
//
// The ordering is the part that matters. The signature is checked before the
// archive is even fetched, so a tampered manifest cannot talk this into
// downloading something it will then happily verify against the tampered
// checksums.
package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBaseURL is where releases live. Overridable so a move to a shorter
// domain costs a flag rather than a rebuild — the same reasoning as install.sh's
// BASE_URL.
const DefaultBaseURL = "https://github.com/sxty9/Holistic/releases"

// maxArtifact caps every download. A release archive is a few tens of megabytes;
// anything past this is either a mistake or someone feeding us a disk.
const maxArtifact = 512 << 20

type Client struct {
	BaseURL string
	// PublicKey verifies the manifest signature. Without it, Fetch refuses to
	// run at all — verifying nothing and reporting success is the failure this
	// whole package exists to prevent.
	PublicKey ed25519.PublicKey
	HTTP      *http.Client
}

// Release is a verified release, unpacked into Dir.
type Release struct {
	Version  string
	Platform string
	Dir      string // the unpacked tree; contains holistic/bin and holistic/deploy
	Archive  string // file name of the archive, as listed in the manifest
	SHA256   string
}

// ParsePublicKey reads the base64-of-PEM form the build injects.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" || strings.Contains(b64, "REPLACE_ME") {
		return nil, errors.New("this build carries no release key, so it cannot verify anything")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("release key is not valid base64: %w", err)
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("release key is not a PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release key is not a public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release key is %T, not Ed25519", pub)
	}
	return ed, nil
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return DefaultBaseURL
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (c *Client) get(url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		// The installer pins --proto '=https' for the same reason: a redirect to
		// plain HTTP would put the manifest on the wire for anyone to rewrite,
		// and the signature check would then be verifying the attacker's file
		// against the attacker's signature.
		return nil, fmt.Errorf("refusing a non-HTTPS URL: %s", url)
	}
	resp, err := c.client().Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxArtifact))
}

// Fetch downloads, verifies and unpacks a release into dir.
//
// version is a tag such as "v0.0.2", or "latest".
func (c *Client) Fetch(dir, platform, version string) (*Release, error) {
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("no release key: refusing to verify nothing and call it verified")
	}

	base := c.base() + "/download/" + version
	if version == "latest" {
		base = c.base() + "/latest/download"
	}

	sums, err := c.get(base + "/SHA256SUMS")
	if err != nil {
		return nil, fmt.Errorf("could not fetch the release manifest: %w", err)
	}
	sig, err := c.get(base + "/SHA256SUMS.sig")
	if err != nil {
		return nil, fmt.Errorf("the release has no signature, so it will not be installed: %w", err)
	}
	if !ed25519.Verify(c.PublicKey, sums, sig) {
		return nil, errors.New("the release manifest is not signed by the key this build trusts.\n" +
			"Nothing was downloaded past the manifest and nothing was changed.\n" +
			"Either the download was tampered with, or this binary and that release\n" +
			"come from different release lines. Do not work around it.")
	}

	archive := "holistic-" + platform + ".tar.gz"
	want, err := checksumOf(sums, archive)
	if err != nil {
		return nil, err
	}

	blob, err := c.get(base + "/" + archive)
	if err != nil {
		return nil, fmt.Errorf("could not fetch %s: %w", archive, err)
	}
	sum := sha256.Sum256(blob)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("%s does not match the signed manifest.\n  expected  %s\n  got       %s\n"+
			"Nothing has been unpacked. This is usually an interrupted download —\n"+
			"run it again. If it fails twice, stop and ask where the file came from.",
			archive, want, got)
	}

	if err := untar(blob, dir); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, "holistic", "bin")); err != nil {
		return nil, errors.New("the archive does not look like a Holistic release")
	}

	return &Release{Version: version, Platform: platform, Dir: dir, Archive: archive, SHA256: want}, nil
}

// checksumOf reads one entry out of a sha256sum-format manifest. The " *name"
// form is accepted alongside " name" because sha256sum writes the star for
// binary mode and the manifest is generated by whichever of the two the build
// host has.
func checksumOf(manifest []byte, name string) (string, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if f[1] == name || f[1] == "*"+name {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("%s is not listed in the signed manifest", name)
}

func untar(blob []byte, dir string) error {
	zr, err := gzip.NewReader(strings.NewReader(string(blob)))
	if err != nil {
		return fmt.Errorf("the archive is not gzip: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		// Reject anything that would land outside dir. A tar entry naming
		// "../../etc/passwd" is the oldest trick there is, and this code runs as
		// root by necessity.
		target, err := safeJoin(dir, h.Name)
		if err != nil {
			return err
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxArtifact)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			// Symlinks, devices, hard links. A release is binaries, units and
			// example configuration; none of it needs them, and each is a way
			// out of the directory.
			return fmt.Errorf("%s: unexpected entry type %q in the archive", h.Name, h.Typeflag)
		}
	}
}

// safeJoin refuses an entry name that tries to leave dir, rather than
// normalising it into something harmless.
//
// Rooting the name and cleaning it — filepath.Clean("/"+name) — does stop the
// escape, and that was the first version of this. But it stops it *silently*:
// "../escaped" becomes "/escaped" and lands inside the directory under a name
// nobody asked for, so a deliberately malicious archive installs most of the
// way and reports success. An archive that tries this is not one to
// half-install, so the traversal is the error rather than something to route
// around.
func safeJoin(dir, name string) (string, error) {
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%s: absolute paths are not allowed in a release archive", name)
	}
	for _, seg := range strings.Split(filepath.ToSlash(name), "/") {
		if seg == ".." {
			return "", fmt.Errorf("%s: entry would climb out of the unpack directory", name)
		}
	}
	target := filepath.Join(dir, filepath.Clean(name))
	// Belt and braces: even with the segment check above, refuse anything that
	// does not end up under dir. Symlinked temp directories and case-folding
	// filesystems have both produced surprises here for other people.
	if target != filepath.Clean(dir) &&
		!strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s: entry would land outside the unpack directory", name)
	}
	return target, nil
}
