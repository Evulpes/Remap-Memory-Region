using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using static Remap_Memory_Region.NativeMethods.Winnt;
using static Remap_Memory_Region.NativeMethods.Winnt.AccessMask;
using static Remap_Memory_Region.NativeMethods.Winnt.MemoryAllocationType;
using static Remap_Memory_Region.NativeMethods.Winnt.MemoryProtectionConstraints;
using static Remap_Memory_Region.NativeMethods.Winnt.SectionProtectionConstraints;
namespace Remap_Memory_Region
{
    class Program : NativeMethods
    {
        static void Main(string[] args)
        {
            Process targetProc = Process.GetProcessesByName("SomeProcess").FirstOrDefault();

            //Open a handle to the target process
            IntPtr hProcess = Processthreadsapi.OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, targetProc.Id);
            if (hProcess == IntPtr.Zero)
                NativeError("OpenProcess");


            //Query the process and get the baseInfo structure.
            if (Memoryapi.VirtualQueryEx
            (
                hProcess,
                targetProc.MainModule.BaseAddress,
                out MEMORY_BASIC_INFORMATION basicInfo,
                Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0
            )
                NativeError("VirtualQueryEx");


            Ntpsapi.NtSuspendProcess(hProcess);

            //Allocate a buffer to read the region to.
            IntPtr buffer = Memoryapi.VirtualAlloc(IntPtr.Zero, (int)basicInfo.regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (buffer == IntPtr.Zero)
                NativeError("VirtualAlloc");

            //Read the data into the buffer.
            if (!Memoryapi.ReadProcessMemory(hProcess, basicInfo.baseAddress, buffer, (int)basicInfo.regionSize, out _))
                NativeError("ReadProcessMemory");

            IntPtr hSection = IntPtr.Zero;
            long sectionMaxSize = (long)basicInfo.regionSize;


            //Create a section object to share between local and remote process.
            if (Ntifs.NtCreateSection
            (
                ref hSection,
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref sectionMaxSize,
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                IntPtr.Zero
            )
            != Ntifs.Ntstatus.STATUS_SUCCESS)
                NativeError("NtCreateSection");

            //Unmap the memory at the base of the remote process.
            if (Ntapi.NtUnmapViewOfSection(hProcess, basicInfo.baseAddress) != Ntifs.Ntstatus.STATUS_SUCCESS)
                NativeError("NtUnmapViewOfSection");

            IntPtr viewBase = basicInfo.baseAddress;
            long sectionOffset = default;
            uint viewSize = default;

            //Map a region back to the original region location with new rights.
            if (Ntapi.NtMapViewOfSection
            (
                hSection,
                hProcess,
                ref viewBase,
                UIntPtr.Zero,
                (int)basicInfo.regionSize,
                ref sectionOffset,
                ref viewSize,
                2 /*ViewUnmap*/,
                0,
                PAGE_EXECUTE_READWRITE /*Set to the desired new access rights*/

            ) != Ntifs.Ntstatus.STATUS_SUCCESS)
                NativeError("NtMapViewOfSection");

            //Write the memory back to the updated region.
            if (!Memoryapi.WriteProcessMemory(hProcess, viewBase, buffer, (int)viewSize, out IntPtr _))
                NativeError("WriteProcessMemory");

            //Empty the buffer
            Memoryapi.VirtualFree(buffer, 0, MemFree.MEM_RELEASE);

            //Close the section handle
            Handleapi.CloseHandle(hSection);

            //Resume the process
            Ntpsapi.NtResumeProcess(hProcess);

        }
        static void NativeError(string nativeMethod)
        {
            int lastWin32Error = Marshal.GetLastWin32Error();
            Console.Write($"{nativeMethod} failed. Last Error: {lastWin32Error}");
            Environment.Exit(lastWin32Error);
        }
    }
}
