using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DriverController
{
    class Program
    {
        const uint FILE_SHARE_READ = 1;
        const uint OPEN_EXISTING = 3;

        const uint IOCTL_CUSTOM_COMMAND = 0x800 + 2;
        const uint IOCTL_STOP_PROTECTION = 0x800 + 3;
        const uint IOCTL_START_PROTECTION = 0x800 + 4;

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
            Console.Write("Select option: 1 / Send message to driver, 2 / Stop driver protection / 3 Start driver protection: ");

            var result = Console.ReadLine().Trim();

            if (result == "1")
            {
                IntPtr deviceHandle = CreateFile(
                    "\\\\.\\CANOMONSTER",
                    0,
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

                    var ctlCode = (uint)CTL_CODE(0x00000022, (int)IOCTL_CUSTOM_COMMAND, 0, 0);

                    DeviceIoControl(
                        deviceHandle,
                        ctlCode,
                        inputDataPtr,
                        (uint)inputData.Length,
                        IntPtr.Zero,
                        0,
                        ref bytesReturned,
                        IntPtr.Zero
                    );

                    CloseHandle(deviceHandle);
                }
            }
            else if (result == "2")
            {
                IntPtr deviceHandle = CreateFile(
                    "\\\\.\\CANOMONSTER",
                    0,
                    FILE_SHARE_READ,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero
                );

                if (deviceHandle != IntPtr.Zero)
                {
                    byte[] inputData = Encoding.UTF8.GetBytes("YourData");
                    uint bytesReturned = 0;

                    IntPtr inputDataPtr = Marshal.UnsafeAddrOfPinnedArrayElement(inputData, 0);

                    var ctlCode = (uint)CTL_CODE(0x00000022, (int)IOCTL_STOP_PROTECTION, 0, 0);

                    DeviceIoControl(
                        deviceHandle,
                        ctlCode,
                        inputDataPtr,
                        (uint)inputData.Length,
                        IntPtr.Zero,
                        0,
                        ref bytesReturned,
                        IntPtr.Zero
                    );

                    CloseHandle(deviceHandle);
                }
            }
            else if (result == "3")
            {
                IntPtr deviceHandle = CreateFile(
                    "\\\\.\\CANOMONSTER",
                    0,
                    FILE_SHARE_READ,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero
                );

                if (deviceHandle != IntPtr.Zero)
                {
                    byte[] inputData = Encoding.UTF8.GetBytes("YourData");
                    uint bytesReturned = 0;

                    IntPtr inputDataPtr = Marshal.UnsafeAddrOfPinnedArrayElement(inputData, 0);

                    var ctlCode = (uint)CTL_CODE(0x00000022, (int)IOCTL_START_PROTECTION, 0, 0);

                    DeviceIoControl(
                        deviceHandle,
                        ctlCode,
                        inputDataPtr,
                        (uint)inputData.Length,
                        IntPtr.Zero,
                        0,
                        ref bytesReturned,
                        IntPtr.Zero
                    );

                    CloseHandle(deviceHandle);
                }
            }

            Console.ReadKey();
        }

        public static int CTL_CODE(int DeviceType, int Function, int Method, int Access)
        {
            return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2)
              | (Method));
        }
    }
}
