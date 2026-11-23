package winsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrReparsePoint is returned when any component of a path is an NTFS junction,
// symlink, or other reparse point.
var ErrReparsePoint = errors.New("path contains a reparse point (junction or symlink)")

// ErrFileTooLarge is returned when a file exceeds the configured read cap.
var ErrFileTooLarge = errors.New("file exceeds size limit")

const (
	objCaseInsensitive = 0x00000040

	fileOpen   = 1
	fileCreate = 2
	fileOpenIf = 3

	fileDirectoryFile         = 0x00000001
	fileSynchronousIoNonalert = 0x00000020
	fileNonDirectoryFile      = 0x00000040
	fileOpenForBackupIntent   = 0x00004000
	fileOpenReparsePoint      = 0x00200000

	fileAttributeDirectory    = 0x00000010
	fileAttributeReparsePoint = 0x00000400

	fileShareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

	AccessDelete         = 0x00010000
	AccessReadControl    = 0x00020000
	AccessWriteOwner     = 0x00080000
	AccessSystemSecurity = 0x01000000
)

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procSetFileInformationByHandle = kernel32.NewProc("SetFileInformationByHandle")
	procSetEndOfFile             = kernel32.NewProc("SetEndOfFile")
)

func ntErr(err error) error {
	if err == nil {
		return nil
	}
	var st windows.NTStatus
	if errors.As(err, &st) {
		return st.Errno()
	}
	return err
}

func ntOpenRelative(parent windows.Handle, name string, access uint32, disposition uint32, options uint32) (windows.Handle, error) {
	us, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    us,
		Attributes:    objCaseInsensitive,
	}
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, fileShareAll, disposition, options, 0, 0)
	if err != nil {
		return 0, ntErr(err)
	}
	return h, nil
}

func checkNoReparse(h windows.Handle, requireDir bool) (windows.ByHandleFileInformation, error) {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fi, err
	}
	if fi.FileAttributes&fileAttributeReparsePoint != 0 {
		return fi, ErrReparsePoint
	}
	if requireDir && fi.FileAttributes&fileAttributeDirectory == 0 {
		return fi, fmt.Errorf("expected directory")
	}
	return fi, nil
}

func splitDrivePath(path string) (root string, parts []string, err error) {
	clean := filepath.Clean(path)
	vol := filepath.VolumeName(clean)
	if len(vol) != 2 || vol[1] != ':' {
		return "", nil, fmt.Errorf("unsupported path %q: expected drive-letter path", path)
	}
	rest := strings.TrimPrefix(clean[len(vol):], `\`)
	if rest == "" {
		return vol + `\`, nil, nil
	}
	for _, seg := range strings.Split(rest, `\`) {
		if seg != "" {
			parts = append(parts, seg)
		}
	}
	return vol + `\`, parts, nil
}

func openParentNoReparse(path string, createDirs bool) (windows.Handle, string, error) {
	root, parts, err := splitDrivePath(path)
	if err != nil {
		return 0, "", err
	}
	if len(parts) == 0 {
		return 0, "", fmt.Errorf("path %q has no leaf component", path)
	}
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0, "", err
	}
	cur, err := windows.CreateFile(rootPtr, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, fileShareAll,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, "", err
	}
	disp := uint32(fileOpen)
	if createDirs {
		disp = fileOpenIf
	}
	opts := uint32(fileDirectoryFile | fileOpenReparsePoint | fileSynchronousIoNonalert | fileOpenForBackupIntent)
	for _, seg := range parts[:len(parts)-1] {
		next, err := ntOpenRelative(cur, seg, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, disp, opts)
		windows.CloseHandle(cur)
		if err != nil {
			return 0, "", err
		}
		if _, err := checkNoReparse(next, true); err != nil {
			windows.CloseHandle(next)
			return 0, "", err
		}
		cur = next
	}
	return cur, parts[len(parts)-1], nil
}

func openLeafNoReparse(path string, access uint32, disposition uint32, options uint32, createDirs bool, requireDir bool) (windows.Handle, error) {
	root, parts, err := splitDrivePath(path)
	if err != nil {
		return 0, err
	}
	if len(parts) == 0 {
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			return 0, err
		}
		return windows.CreateFile(rootPtr, access, fileShareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	}
	parent, leaf, err := openParentNoReparse(path, createDirs)
	if err != nil {
		return 0, err
	}
	h, err := ntOpenRelative(parent, leaf, access, disposition, options)
	windows.CloseHandle(parent)
	if err != nil {
		return 0, err
	}
	if _, err := checkNoReparse(h, requireDir); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// OpenNoReparse opens an existing file or directory without following any
// NTFS reparse points (junctions or symlinks) along the path.
func OpenNoReparse(path string, access uint32, extraOptions uint32) (windows.Handle, error) {
	opts := uint32(fileOpenReparsePoint|fileSynchronousIoNonalert|fileOpenForBackupIntent) | extraOptions
	return openLeafNoReparse(path, access, fileOpen, opts, false, false)
}

// OpenFileNoReparse opens an existing non-directory file without following
// any NTFS reparse points along the path.
func OpenFileNoReparse(path string, access uint32, extraOptions uint32) (windows.Handle, error) {
	opts := uint32(fileNonDirectoryFile|fileOpenReparsePoint|fileSynchronousIoNonalert|fileOpenForBackupIntent) | extraOptions
	return openLeafNoReparse(path, access, fileOpen, opts, false, false)
}

// OpenFileNoReparseAsync opens an existing non-directory file for overlapped
// (asynchronous) I/O without following any NTFS reparse points.
func OpenFileNoReparseAsync(path string, access uint32) (windows.Handle, error) {
	opts := uint32(fileNonDirectoryFile | fileOpenReparsePoint | fileOpenForBackupIntent)
	return openLeafNoReparse(path, access|windows.FILE_READ_ATTRIBUTES, fileOpen, opts, false, false)
}

// OpenDirNoReparse opens (and optionally creates) a directory without
// following any NTFS reparse points along the path.
func OpenDirNoReparse(path string, access uint32, create bool) (windows.Handle, error) {
	disp := uint32(fileOpen)
	if create {
		disp = fileOpenIf
	}
	opts := uint32(fileDirectoryFile | fileOpenReparsePoint | fileSynchronousIoNonalert | fileOpenForBackupIntent)
	return openLeafNoReparse(path, access, disp, opts, create, true)
}

// MkdirAllNoReparse creates dir and any missing parent directories, refusing
// to traverse or create through any reparse point.
func MkdirAllNoReparse(dir string) error {
	h, err := OpenDirNoReparse(dir, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, true)
	if err != nil {
		return err
	}
	windows.CloseHandle(h)
	return nil
}

// ReadFileNoReparse reads an existing file without following reparse points.
func ReadFileNoReparse(path string) ([]byte, error) {
	h, err := OpenFileNoReparse(path, windows.GENERIC_READ|windows.SYNCHRONIZE, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	return io.ReadAll(f)
}

// ReadFileNoReparseLimit reads up to maxBytes from an existing regular file
// without following reparse points, returning ErrFileTooLarge if exceeded.
func ReadFileNoReparseLimit(path string, maxBytes int64) ([]byte, error) {
	h, err := OpenFileNoReparse(path, windows.GENERIC_READ|windows.SYNCHRONIZE, 0)
	if err != nil {
		return nil, err
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	size := int64(fi.FileSizeHigh)<<32 | int64(fi.FileSizeLow)
	if maxBytes >= 0 && size > maxBytes {
		windows.CloseHandle(h)
		return nil, ErrFileTooLarge
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if maxBytes < 0 {
		return io.ReadAll(f)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, ErrFileTooLarge
	}
	return b, nil
}

// WriteFileNewNoReparse creates a brand-new regular file (failing if it already
// exists, including as a reparse point) without following reparse points in
// parent directories.
func WriteFileNewNoReparse(path string, data []byte) error {
	opts := uint32(fileNonDirectoryFile | fileOpenReparsePoint | fileSynchronousIoNonalert | fileOpenForBackupIntent)
	h, err := openLeafNoReparse(path, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, fileCreate, opts, true, false)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// OverwriteFileNoReparse truncates and rewrites an existing regular file in
// place without following reparse points, preserving its handle-level SACL.
func OverwriteFileNoReparse(path string, data []byte) error {
	h, err := OpenFileNoReparse(path, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return err
	}
	if r, _, e := procSetEndOfFile.Call(uintptr(h)); r == 0 {
		windows.CloseHandle(h)
		return fmt.Errorf("SetEndOfFile: %w", e)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

type fileDispositionInfo struct {
	DeleteFile byte
}

// DeleteFileNoReparse deletes an existing file by handle without following
// reparse points.
func DeleteFileNoReparse(path string) error {
	h, err := OpenFileNoReparse(path, AccessDelete|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return err
	}
	disp := fileDispositionInfo{DeleteFile: 1}
	r, _, e := procSetFileInformationByHandle.Call(uintptr(h), 4 /* FileDispositionInfo */, uintptr(unsafe.Pointer(&disp)), 1)
	windows.CloseHandle(h)
	if r == 0 {
		return e
	}
	return nil
}

// RemoveEmptyDirNoReparse deletes an empty directory by handle without
// following reparse points.
func RemoveEmptyDirNoReparse(dir string) error {
	h, err := OpenDirNoReparse(dir, AccessDelete|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, false)
	if err != nil {
		return err
	}
	disp := fileDispositionInfo{DeleteFile: 1}
	r, _, e := procSetFileInformationByHandle.Call(uintptr(h), 4 /* FileDispositionInfo */, uintptr(unsafe.Pointer(&disp)), 1)
	windows.CloseHandle(h)
	if r == 0 {
		return e
	}
	return nil
}

// StatNoReparse returns file info for path without following reparse points.
func StatNoReparse(path string) (os.FileInfo, error) {
	h, err := OpenNoReparse(path, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0)
	if err != nil {
		return nil, err
	}
	var fi windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &fi)
	windows.CloseHandle(h)
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0o644)
	if fi.FileAttributes&fileAttributeDirectory != 0 {
		mode = os.ModeDir | 0o755
	}
	size := int64(fi.FileSizeHigh)<<32 | int64(fi.FileSizeLow)
	modTime := time.Unix(0, fi.LastWriteTime.Nanoseconds())
	return safeFileInfo{
		name:    filepath.Base(path),
		size:    size,
		mode:    mode,
		modTime: modTime,
	}, nil
}

// ReadDirNoReparse verifies dir contains no reparse points and returns its entries.
func ReadDirNoReparse(dir string) ([]os.DirEntry, error) {
	h, err := OpenDirNoReparse(dir, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, false)
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(h)
	return os.ReadDir(dir)
}

type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// SetBasicAttributesByHandle updates file attributes on an already-verified handle.
func SetBasicAttributesByHandle(h windows.Handle, attrs uint32) error {
	info := fileBasicInfo{FileAttributes: attrs}
	r, _, e := procSetFileInformationByHandle.Call(uintptr(h), 0 /* FileBasicInfo */, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		return e
	}
	return nil
}

type safeFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi safeFileInfo) Name() string       { return fi.name }
func (fi safeFileInfo) Size() int64        { return fi.size }
func (fi safeFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi safeFileInfo) ModTime() time.Time { return fi.modTime }
func (fi safeFileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi safeFileInfo) Sys() any           { return nil }
