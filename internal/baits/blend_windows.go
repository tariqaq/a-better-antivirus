package baits

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// A bait's tripwire on Windows is an audit rule on the file (see
// winsec.SetBaitAudit): reads of it land in the Security event log.

// SetTripwire puts the tripwire on a bait file. Requires admin.
func SetTripwire(path string) error { return winsec.SetBaitAudit(path) }

// HasTripwire reports whether the file still has its tripwire.
func HasTripwire(path string) (bool, error) { return winsec.HasBaitAudit(path) }

// ClearTripwire takes the tripwire off again.
func ClearTripwire(path string) error { return winsec.ClearAudit(path) }

func fileTime(t time.Time) *windows.Filetime {
	ft := windows.NsecToFiletime(t.UnixNano())
	return &ft
}

func setTimes(path string, created, accessed, written time.Time) {
	h, err := winsec.OpenNoReparse(path, windows.FILE_WRITE_ATTRIBUTES|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.SetFileTime(h, fileTime(created), fileTime(accessed), fileTime(written))
}

func getTimes(path string) (created, written time.Time, ok bool) {
	h, err := winsec.OpenNoReparse(path, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return created, written, false
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &fi) != nil {
		return created, written, false
	}
	return time.Unix(0, fi.CreationTime.Nanoseconds()), time.Unix(0, fi.LastWriteTime.Nanoseconds()), true
}

// ownedBy makes sid the owner of path, when it isn't already. (Needs the
// restore privilege, which an elevated installer and the service have.)
func ownedBy(path, sid string) {
	if sid == "" {
		return
	}
	want, err := windows.StringToSid(sid)
	if err != nil {
		return
	}
	winsec.EnablePrivilege("SeRestorePrivilege")
	h, err := winsec.OpenNoReparse(path, winsec.AccessReadControl|winsec.AccessWriteOwner|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	if sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if cur, _, err := sd.Owner(); err == nil && cur != nil && cur.Equals(want) {
			return
		}
	}
	windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, want, nil, nil, nil)
}

// indexedLikeFolder gives a bait the same "index this file" setting as the
// folder it's in (which is what any file created there gets).
func indexedLikeFolder(path string) {
	fh, err := winsec.OpenNoReparse(path, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(fh)
	dh, err := winsec.OpenNoReparse(filepath.Dir(path), windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(dh)
	var ffi, dfi windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(fh, &ffi) != nil || windows.GetFileInformationByHandle(dh, &dfi) != nil {
		return
	}
	const noIndex = windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	if ffi.FileAttributes&noIndex == dfi.FileAttributes&noIndex {
		return
	}
	winsec.SetBasicAttributesByHandle(fh, ffi.FileAttributes&^noIndex|dfi.FileAttributes&noIndex)
}

// asOwner runs fn, which plants or removes files at or around path. On
// Windows, ordinary users can create NTFS junctions in folders they own, so
// bait file, directory, and security operations open every path component with
// FILE_OPEN_REPARSE_POINT and act directly on the verified handle instead of
// following junctions or symlinks.
func asOwner(path string, fn func()) error {
	fn()
	return nil
}

func safeMkdirAll(dir string) error                        { return winsec.MkdirAllNoReparse(dir) }
func safeReadFile(path string) ([]byte, error)             { return winsec.ReadFileNoReparse(path) }
func safeReadFileLimit(path string, n int64) ([]byte, error) { return winsec.ReadFileNoReparseLimit(path, n) }
func safeWriteFileNew(path string, data []byte) error { return winsec.WriteFileNewNoReparse(path, data) }
func safeOverwriteInPlace(path string, data []byte) error {
	return winsec.OverwriteFileNoReparse(path, data)
}
func safeRemoveFile(path string) error            { return winsec.DeleteFileNoReparse(path) }
func safeRemoveEmptyDir(dir string) error         { return winsec.RemoveEmptyDirNoReparse(dir) }
func safeStat(path string) (os.FileInfo, error)   { return winsec.StatNoReparse(path) }
func safeReadDir(dir string) ([]os.DirEntry, error) { return winsec.ReadDirNoReparse(dir) }
func isReparseErr(err error) bool                 { return errors.Is(err, winsec.ErrReparsePoint) }
