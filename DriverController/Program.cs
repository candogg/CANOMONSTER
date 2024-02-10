using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DriverController
{
    class Program
    {
        const uint FILE_SHARE_READ = 1;
        const uint OPEN_EXISTING = 3;

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
            Console.Write("Select option: 1 / Stop driver protection / 2 Start driver protection: ");

            var result = Console.ReadLine().Trim();

            while (result != "x" || result != "X")
            {
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
                        byte[] inputData = Encoding.UTF8.GetBytes("f4ac987a-b8a3-4df1-a4c9-da9c2f0a5730");
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
                        byte[] inputData = Encoding.UTF8.GetBytes("966139b8-8216-4034-872e-7268a92a18ef");
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

                Console.Write("Select option: 1 / Stop driver protection / 2 Start driver protection: ");

                result = Console.ReadLine().Trim();
            }

            Console.Write("Çıkmak için bir tuşa basın");

            Console.ReadKey();
        }

        public static int CTL_CODE(int DeviceType, int Function, int Method, int Access)
        {
            return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2)
              | (Method));
        }
    }
}
