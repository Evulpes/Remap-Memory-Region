using System;
using System.Runtime.InteropServices;

namespace Remap_Memory_Region
{
    class NativeMethods
    {
        protected static class Handleapi
        {
            [DllImport("Kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);
        }
        protected static class Memoryapi
        {
            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int size, out IntPtr lpNumberOfBytesRead);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, Winnt.MemoryAllocationType flAllocationType, Winnt.MemoryProtectionConstraints flProtect);

            [DllImport("Kernel32.dll")]
            public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, Winnt.MemFree dwFreeType);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern int VirtualQueryEx(IntPtr handle, IntPtr lpAddress, out Winnt.MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        }

        protected static class Ntapi
        {
            [DllImport("ntdll.dll")]
            public static extern Ntifs.Ntstatus NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress);

            [DllImport("ntdll.dll")]
            public static extern Ntifs.Ntstatus NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, UIntPtr ZeroBits, int commitSize, ref long SectionOffset, ref uint ViewSize, uint InheritDisposition, Winnt.MemoryAllocationType allocationType, Winnt.MemoryProtectionConstraints win32Protect);
        }
        protected static class Ntifs
        {
            [DllImport("ntdll.dll")]
            public static extern Ntstatus NtCreateSection(ref IntPtr sectionHandle, Winnt.AccessMask DesiredAccess, IntPtr objectAttributes, ref long MaximumSize, Winnt.MemoryProtectionConstraints SectionPageProtection, Winnt.SectionProtectionConstraints AllocationAttributes, IntPtr fileHandle);

            public enum Ntstatus : uint
            {
                STATUS_ACCESS_VIOLATION = 3221225477,
                STATUS_SUCCESS = 0,
                STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
                STATUS_INVALID_FILE_FOR_SECTION = 0xC0000020,
                STATUS_INVALID_PAGE_PROTECTION = 0xC0000045,
                STATUS_MAPPED_FILE_SIZE_ZERO = 0xC000011E,
                STATUS_SECTION_TOO_BIG = 0xC0000040,
            }
        }
        protected static class Ntpsapi
        {
            [DllImport("ntdll.dll")]
            public static extern void NtResumeProcess(IntPtr processHandle);

            [DllImport("ntdll.dll")]
            public static extern void NtSuspendProcess(IntPtr processHandle);
        }
        protected static class Processthreadsapi
        {
            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(Winnt.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        }
        public static class Winnt
        {
            public enum AccessMask : uint
            {

                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010,
                SECTION_MAP_EXECUTE_EXPLICIT = 0x0020,
                SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE)
            }
            public enum MemoryAllocationType
            {
                MEM_COMMIT = 0x00001000,
                MEM_RESERVE = 0x00002000,
            }
            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr baseAddress;
                public IntPtr allocationBase;
                public MemoryProtectionConstraints allocationProtect;
                public IntPtr regionSize;
                public State state;
                public MemoryProtectionConstraints protect;
                public Type type;
            }
            public enum MemoryProtectionConstraints : uint
            {
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_NOACCESS = 0x01,
                PAGE_READONLY = 0x02,
                PAGE_READWRITE = 0x04,
                PAGE_WRITECOPY = 0x08,
                PAGE_TARGETS_INVALID = 0x40000000,
                PAGE_TARGETS_NO_UPDATE = 0x40000000,
                PAGE_GUARD = 0x100,
                PAGE_NOCACHE = 0x200,
                PAGE_WRITECOMBINE = 0x400,

            }
            public enum MemFree
            {
                MEM_RELEASE = 0x00008000,
            }
            public enum ProcessAccessFlags
            {
                PROCESS_ALL_ACCESS = 0xFFFF,
            }
            public enum SectionProtectionConstraints
            {
                SEC_COMMIT = 0x08000000,
            }
            public enum State
            {
                MEM_COMMIT = 0x1000,
                MEM_FREE = 0x10000,
                MEM_RESERVE = 0x2000,
            }
            public enum Type
            {
                MEM_IMAGE = 0x1000000,
                MEM_MAPPED = 0x40000,
                MEM_PRIVATE = 0x20000,
            }
        }

    }









}
