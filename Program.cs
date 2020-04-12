using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;

namespace Remap_Memory_Region
{
    class Program : NativeMethods
    {
        static void Main(string[] args)
        {
            Process process = Process.GetProcessesByName("notepad").FirstOrDefault();
            IntPtr hProcess = Processthreadsapi.OpenProcess(Winnt.ProcessAccessFlags.PROCESS_ALL_ACCESS, false, process.Id);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed on OpenProcess. Handle is invalid.");
                return;
            }

            if (Memoryapi.VirtualQueryEx(hProcess, process.MainModule.BaseAddress, out Winnt.MEMORY_BASIC_INFORMATION basicInformation, Marshal.SizeOf(typeof(Winnt.MEMORY_BASIC_INFORMATION))) == 0)
            {
                Console.WriteLine("Failed on VirtualQueryEx. Return is 0 bytes.");
                return;
            }
            IntPtr regionBase = basicInformation.baseAddress;
            IntPtr regionSize = basicInformation.regionSize;
            Ntpsapi.NtSuspendProcess(hProcess);
            RemapMemoryRegion(hProcess, regionBase, regionSize.ToInt32(), Winnt.MemoryProtectionConstraints.PAGE_WRITECOMBINE);            //MISSING VIRTUALALLOC
            Ntpsapi.NtResumeProcess(hProcess);
            Handleapi.CloseHandle(hProcess);

        }
        public static bool RemapMemoryRegion(IntPtr processHandle, IntPtr baseAddress, int regionSize, Winnt.MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = Memoryapi.VirtualAlloc(IntPtr.Zero, regionSize, Winnt.MemoryAllocationType.MEM_COMMIT | Winnt.MemoryAllocationType.MEM_RESERVE, Winnt.MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return false;

            IntPtr copyBuf = Memoryapi.VirtualAlloc(IntPtr.Zero, regionSize, Winnt.MemoryAllocationType.MEM_COMMIT | Winnt.MemoryAllocationType.MEM_RESERVE, Winnt.MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (!Memoryapi.ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return false;
            
            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;


            Ntifs.Ntstatus status = Ntifs.NtCreateSection(ref sectionHandle, Winnt.AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, Winnt.MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, Winnt.SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);
            
            if (status != Ntifs.Ntstatus.STATUS_SUCCESS)
                return false;

            status = Ntapi.NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntifs.Ntstatus.STATUS_SUCCESS)
                return false;



            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = Ntapi.NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               Winnt.MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (status != Ntifs.Ntstatus.STATUS_SUCCESS)
                return false;

            if (!Memoryapi.WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return false;

            if(!Memoryapi.VirtualFree(copyBuf, 0, Winnt.MemFree.MEM_RELEASE))
                return false;

            return true;

        }
    }
}
