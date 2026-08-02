package localsync

import (
	"crypto/sha256"
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// HashFile streams SHA-256 of a regular file opened without following the final
// symlink when the platform supports it (Unix O_NOFOLLOW via openFileNOFOLLOW).
func HashFile(nativePath string) (codec.Digest, int64, error) {
	f, err := openFileNOFOLLOW(nativePath)
	if err != nil {
		return codec.Digest{}, 0, wrap(KindRead, "hash", "", err)
	}
	defer f.Close()
	return HashOpenedFile(f)
}

// HashOpenedFile streams SHA-256 of an already-opened regular file (M3d ScanAt).
func HashOpenedFile(f *os.File) (codec.Digest, int64, error) {
	if f == nil {
		return codec.Digest{}, 0, invalidArg("hash", "nil file")
	}
	st, err := f.Stat()
	if err != nil {
		return codec.Digest{}, 0, wrap(KindRead, "hash", "", err)
	}
	if !st.Mode().IsRegular() {
		return codec.Digest{}, 0, unsupported("hash", "", "not a regular file")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return codec.Digest{}, 0, wrap(KindRead, "hash", "", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return codec.Digest{}, 0, wrap(KindRead, "hash", "", err)
	}
	var d codec.Digest
	copy(d[:], h.Sum(nil))
	return d, n, nil
}

// HashReader returns SHA-256 of r.
func HashReader(r io.Reader) (codec.Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return codec.Digest{}, err
	}
	var d codec.Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}

func openFileRead(nativePath string) (*os.File, error) {
	return openFileNOFOLLOW(nativePath)
}
