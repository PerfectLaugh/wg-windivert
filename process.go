package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const PROCESS_QUERY_LIMITED_INFORMATION uint32 = 0x1000

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
)

func processPidToName(pid uint32) (string, error) {
	handle, err := syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(handle)

	return queryFullProcessImageName(handle, 0)
}

func queryFullProcessImageName(
	process syscall.Handle,
	flags uint32,
) (s string, err error) {
	var bufferSize uint32 = 32 * 1024
	buffer := make([]uint16, bufferSize)

	r1, _, e1 := syscall.Syscall6(
		procQueryFullProcessImageNameW.Addr(),
		4,
		uintptr(process),
		uintptr(flags),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
		0,
	)
	if r1 == 0 {
		if e1 != 0 {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}
	if err == nil {
		s = syscall.UTF16ToString(buffer[:bufferSize])
	}
	return
}
