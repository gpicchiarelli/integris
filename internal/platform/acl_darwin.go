//go:build darwin && cgo

package platform

/*
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/acl.h>
#include <membership.h>

static char *integris_acl_roundtrip(const char *path) {
	acl_t acl = acl_init(1);
	if (acl == NULL) {
		return strdup(strerror(errno));
	}
	acl_entry_t entry;
	if (acl_create_entry(&acl, &entry) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	if (acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	uuid_t uuid;
	if (mbr_uid_to_uuid(getuid(), uuid) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	if (acl_set_qualifier(entry, uuid) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	acl_permset_t perms;
	if (acl_get_permset(entry, &perms) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	if (acl_add_perm(perms, ACL_READ_DATA) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	if (acl_set_file(path, ACL_TYPE_EXTENDED, acl) != 0) {
		char *msg = strdup(strerror(errno));
		acl_free(acl);
		return msg;
	}
	acl_free(acl);
	acl_t got = acl_get_file(path, ACL_TYPE_EXTENDED);
	if (got == NULL) {
		return strdup(strerror(errno));
	}
	acl_free(got);
	return NULL;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const aclSupported = true

func aclRoundTrip(path string) error {
	if path == "" {
		return fmt.Errorf("platform: empty ACL path")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	msg := C.integris_acl_roundtrip(cPath)
	if msg != nil {
		defer C.free(unsafe.Pointer(msg))
		return fmt.Errorf("platform: ACL round-trip: %s", C.GoString(msg))
	}
	return nil
}
