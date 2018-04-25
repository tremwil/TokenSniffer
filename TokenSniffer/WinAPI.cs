using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace TokenSniffer
{
    public static class WinAPI
    {
        public enum MemoryProtection : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum MemoryState : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum MemoryType : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        public struct MEMORY_BASIC_INFO
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public MemoryProtection AllocationProtect;
            public IntPtr RegionSize;
            public MemoryState State;
            public MemoryProtection Protect;
            public MemoryType Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );

        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern void GetSystemInfo(out SYSTEM_INFO Info);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFO lpBuffer, int dwLength);

        [DllImport("kernel32.dll")]
        public static extern int VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr dataPtr,
            int dwSize,
            out int lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int memcmp(IntPtr b1, byte[] b2, IntPtr count);
    }
}
