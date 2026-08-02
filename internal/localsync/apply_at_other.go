//go:build !unix

package localsync

import "os"

// ApplyAt falls back to ambient Apply off unix.
func ApplyAt(srcFD, dstFD *os.File, roots Roots, plan Plan, hooks *ApplyHooks) (ApplyResult, error) {
	_ = srcFD
	_ = dstFD
	return Apply(roots, plan, hooks)
}

// ApplyWithAt falls back to ambient ApplyWith off unix.
func ApplyWithAt(srcFD, dstFD *os.File, roots Roots, plan Plan, opts ApplyOptions) (ApplyResult, error) {
	_ = srcFD
	_ = dstFD
	return ApplyWith(roots, plan, opts)
}
