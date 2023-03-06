# Remap-Memory-Region
## Introduction - It Is Known!
Like that one extra said in Game of Thrones, ["it is known"](https://youtu.be/foqUPiwMiOM). It is known that you cannot set your [Memory Protection Options](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants) on non-private memory greater than the initial level. I say this but I can't source it; I'm SURE Microsoft will have written it down somewhere, so go find it and pull request. However for now, it is just known, unless you go try it.

This restriction creates a bit of a problem in some cases. For example, what if there's a region that only has [PAGE_EXECUTE_READ](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants), as it's initial level, but you want to write to, or modify, its memory? In most cases, you can't. 
You can also think of this as an oppurtunity; what if you have an application that you want to protect from memory edits?

Anyway, in the style of Eminem, ["my name is"](https://www.youtube.com/watch?v=sNPnbI1arSE) and this is just another write-up.

### Play Pretend: Sandstorm Depression.
Let's suppose all these write-ups I do are entirely for ethical purposes, and that I do really have some application I want to protect from memory modifcation. Introducing Sandstorm Depression: Sandstorm Depression are a company that produce triple A games, but so far haven't been able stop this elite h4ck3r group from modifying their games memory. The game is called "Globe of Peacekeeping".

With this scenario in mind, let's look at how Sandstorm Depression can modify the initial page protection level to stop writes to their memory.

### Initial D but it's ERWC
Right so here's a picture I made earlier of what the intitial protection for the base executable looks like in Globe of Peacekeeping:
<p align="center">
  <img src="https://i.imgur.com/iJYqn60.png"/>
</p> 
As shown, all of the segments have initial protection of ERWC (Execute, Read, Write, and Copy), which in terms of security is no good! While the current protection on the .text segment is ER (Execute, Read, NOT Emergency Room), we can just elevate the current rights to allow for Writes and do whatever we feel like doing:
<p align="center">
  <img src="https://i.imgur.com/UeCjMrO.png"/>
</p> 

### Bob The Memory Protection Builder
So we've established that Globe of Peacekeeping isn't very good at keeping it's memory in one peace (tell me I'm funny please), but it could be so let's talk about code; using C# on .NET 5 btw.

We're going to be using an external application to modify the executable for Globe of Peacekeeping, purely because it's a lot simplier to do so. 

#### 1. Don't Pick Up The Phone, You Know He's Only Calling For A Handle To Your Process.
First things first, we're going to need a handle to the Globe of Peacekeeping process, with full access ([PROCESS_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)). We'll use the Process class from C#, and [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) for this:
```csharp
Process targetProc = Process.GetProcessesByName("globeofpeacekeeping").FirstOrDefault();

//Open a handle to the target process
IntPtr hProcess = Processthreadsapi.OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, targetProc.Id);
if (hProcess == IntPtr.Zero)
  NativeError("OpenProcess");
```
If your handle returns zero you've done goof. Try [running as admin](https://docs.microsoft.com/en-us/windows/win32/sbscs/application-manifests) or something; idk do I look like tech support?

#### 2. Give Me Your Region Information, I'm Not A Scam Caller!
Moving on, assuming your handle is A-OK, we're going to need to grab the base address and region size. Fortunately, C# has a nice in-built [Process](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-5.0) class to do this, which makes this relatively simple:
```csharp
IntPtr baseAddress;
int regionSize;

if (sectioned)
{
  //Set the base module address and the size.
  baseAddress = targetProc.MainModule.BaseAddress;
  regionSize = targetProc.MainModule.ModuleMemorySize;
}
```

I'm not going to talk about the sectioned bool for this write-up, because in the scenario context it's not overly relevant.

#### 3. Stop! Hammertime.
Now, because of how we're going to modify the initial rights, we're going to need to pull a [MC Hammer](https://youtu.be/otCpCn0l4Wo) and freeze the process while we make our changes. If we don't, our application will just crash :( We can use [NtSuspendProcess](http://pinvoke.net/default.aspx/ntdll/NtSuspendProcess.html) for this as we're fine suspending everything.

```csharp
Ntpsapi.NtSuspendProcess(hProcess);
```
#### 4. Harry Potter And The Copy Paste Job.
Next, we'll need to create a copy of the entire region and store it into a buffer within our external process. We'll need this as we're basically going to execute [Order 66](https://youtu.be/xSN6BOgrSSU) on the region and temporarily wipe it from Globe of Peacekeeping's memory. After that, we'll then replace it with a copy; first we'll use [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) to reserve some memory in our external process, and then read the memory to that reservation using [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory):
```csharp

//Allocate a buffer to read the region to.
IntPtr buffer = Memoryapi.VirtualAlloc(IntPtr.Zero, regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (buffer == IntPtr.Zero)
    NativeError("VirtualAlloc");

//Read the data into the buffer.
if (!Memoryapi.ReadProcessMemory(hProcess, baseAddress, buffer, regionSize, out _))
    NativeError("ReadProcessMemory");
```
#### 5. Mom Said It's My Go On The Memory!
At this point, we're going to need to create a section object. If you're not familiar with a [section object](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views), check the link. However, in short it's basically a region of memory that we can share between two processes in a specific manner. We'll use [NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection) for this:
```csharp
IntPtr hSection = IntPtr.Zero;
long sectionMaxSize = (long)regionSize;


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
```
#### 5A. Code Atlantis
Now, this section isn't in the repository, so PAY ATTENTION. Because we're downgrading rights, we'll need to map a view of the section to in our process using [NtMapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection), and then write the previously copied data to it.

```csharp
IntPtr viewAddr = IntPtr.Zero;
long localSectionOffset = 0;
uint localViewSize = 0;

if(Ntapi.NtMapViewOfSection
(
    hSection,
    Process.GetCurrentProcess().Handle,
    ref viewAddr,
    UIntPtr.Zero,
    regionSize,
    ref localSectionOffset,
    ref localViewSize,
    2,
    0,
    PAGE_EXECUTE_READWRITE) != Ntifs.Ntstatus.STATUS_SUCCESS
)
    NativeError("NtMapViewOfSection");

 if (!Memoryapi.WriteProcessMemory(Process.GetCurrentProcess().Handle, viewAddr, buffer, (int)localViewSize, out IntPtr _))
    NativeError("WriteProcessMemory");

```

#### 6.  Memory | || || |_
Now that we safely have a copy of the memory, and the Globe of Peacekeeping process is sat in limbo, we can "safely" remove the memory image, and it's initial rights from the process space, using [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection):
```csharp
//Unmap the memory at the base of the remote process.
if (Ntapi.NtUnmapViewOfSection(hProcess, baseAddress) != Ntifs.Ntstatus.STATUS_SUCCESS)
    NativeError("NtUnmapViewOfSection");
```
It now looks like this:

Before:
<p align="center">
  <img src="https://i.imgur.com/uH7j8tc.png"/>
</p> 

After:
<p align="center">
  <img src="https://i.imgur.com/miUey8j.png"/>
</p> 


#### 7. What Was The Previous Heading?
Now that the old memory is gone, and we've written the data to the section, we can map the memory back into Globe of Peacekeeping, via NtMapViewOfSection, using whatever rights we'd like, in this case PAGE_EXECUTE_READ:
```csharp
//Map a region back to the original region location with new rights.
if (Ntapi.NtMapViewOfSection
(
    hSection,
    hProcess,
    ref viewBase,
    UIntPtr.Zero,
    regionSize,
    ref sectionOffset,
    ref viewSize,
    2 /*ViewUnmap*/,
    0,
    PAGE_EXECUTE_READ /*Set to the desired new access rights*/

) != Ntifs.Ntstatus.STATUS_SUCCESS)
    NativeError("NtMapViewOfSection");
```
And we're back to the original memory:
<p align="center">
  <img src="https://i.imgur.com/uH7j8tc.png"/>
</p> 

Except now we can see that the region only has ER access rights, and the initial rights are also set to ER, meaning the rights cannot be elevated past that level:
<p align="center">
  <img src="https://i.imgur.com/3r5HF5j.png"/>
</p> 

And if we attempt to change those rights to allow for writes, we get an error from the debugger:
<p align="center">
  <img src="https://i.imgur.com/ZuuPISi.png"/>
</p> 

#### 8. Carry On Execution
At this point we can to resume the process, using [NtResumeProcess](https://www.pinvoke.net/default.aspx/ntdll/NtResumeProcess.html), and hope it doesn't crash. (Spoiler alert: It doesn't). We should also really clean-up, but our external process is qutting now anyway so I won't bother. If you want to extend the code, just close the section handles and free any used memory.
```csharp
//Resume the process (and hope it doesn't crash instantly)
Ntpsapi.NtResumeProcess(hProcess);
```
