using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DriverController
{
    class Program
    {
        const uint FILE_SHARE_READ = 1;
        const uint OPEN_EXISTING = 3;

        const uint IOCTL_CUSTOM_COMMAND = 0x222000;  // Custom IOCTL code

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            ref uint lpBytesReturned,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        static void Main()
        {
            IntPtr deviceHandle = CreateFile(
                "\\\\.\\CANOMONSTER",    // Replace with your device name
                0,  // Change as needed
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero
            );

            if (deviceHandle != IntPtr.Zero)
            {
                // Prepare your input/output data as needed
                byte[] inputData = Encoding.UTF8.GetBytes("YourData");
                uint bytesReturned = 0;

                IntPtr inputDataPtr = Marshal.UnsafeAddrOfPinnedArrayElement(inputData, 0);

                // Send IOCTL
                var success = DeviceIoControl(
                    deviceHandle,
                    IOCTL_CUSTOM_COMMAND,
                    inputDataPtr,
                    (uint)inputData.Length,
                    IntPtr.Zero,
                    0,
                    ref bytesReturned,
                    IntPtr.Zero
                );

                if (success == 0)
                {
                    // Handle success
                    Console.WriteLine("IOCTL command sent successfully.");
                }
                else
                {
                    // Handle failure
                    Console.WriteLine("IOCTL command failed. Error code: " + Marshal.GetLastWin32Error());
                }

                // Close handle
                CloseHandle(deviceHandle);
            }
            else
            {
                Console.WriteLine("Failed to open device. Error code: " + Marshal.GetLastWin32Error());
            }
        }
    }
}
