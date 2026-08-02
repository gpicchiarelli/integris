//go:build !unix

package localsync

func isNoSpace(err error) bool {
	return false
}
