using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

namespace ProtectedService
{
    public partial class Service1 : ServiceBase
    {
        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        public static extern bool DuplicateTokenEx(
            IntPtr existingTokenHandle,
            uint dwDesiredAccess,
            ref SecurityAttributes lpThreadAttributes,
            int tokenType,
            int impersonationLevel,
            ref IntPtr duplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(
           IntPtr hToken,
           string lpApplicationName,
           string lpCommandLine,
           ref SecurityAttributes lpProcessAttributes,
           ref SecurityAttributes lpThreadAttributes,
           bool bInheritHandle,
           int dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           ref StartupInfo lpStartupInfo,
           out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("wtsapi32.dll")]
        public static extern uint WTSQueryUserToken(uint sessionId, ref IntPtr phToken);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateTokenEx(
            IntPtr existingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int tokenType,
            int impersonationLevel,
            ref IntPtr duplicateTokenHandle);

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            var (isCreated, _, _, _) = InjectProcessToUserSessionNativeInternal(@"C:\windows\system32\cmd.exe", 2);

            while (!isCreated)
            {
                Thread.Sleep(1000);

                (isCreated, _, _, _) = InjectProcessToUserSessionNativeInternal(@"C:\windows\system32\cmd.exe", 2);
            }
        }

        private (bool, int, IntPtr, IntPtr) InjectProcessToUserSessionNativeInternal(string applicationName, int sessionId)
        {
            var ret = false;

            var pi = new ProcessInformation()
            {
                dwProcessId = 0
            };

            var lpEnvironment = IntPtr.Zero;

            try
            {
                var dupedToken = new IntPtr(0);

                var sa = new SecurityAttributes
                {
                    bInheritHandle = false
                };

                sa.Length = Marshal.SizeOf(sa);
                sa.lpSecurityDescriptor = (IntPtr)0;
                var token = GetUserTokenFromSessionInternal(sessionId);

                ret = DuplicateTokenEx(token, 0x10000000, ref sa, 2, 1, ref dupedToken);

                if (ret)
                {
                    var si = new StartupInfo()
                    {
                        lpDesktop = "winsta0\\default",
                        dwFlags = 1,
                        wShowWindow = 1
                    };

                    si.cb = Marshal.SizeOf(si);

                    lpEnvironment = CreateUserEnvironment(dupedToken);

                    ret = CreateProcessAsUser(dupedToken, applicationName, null, ref sa, ref sa, false, 0x00000400 | 0x00000010, lpEnvironment, @"C:\", ref si, out pi);

                    if (ret)
                    {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }

                    ret = CloseHandle(dupedToken);
                }
            }
            catch
            { }

            return (ret, (int)pi.dwProcessId, lpEnvironment, pi.hProcess);
        }

        private IntPtr CreateUserEnvironment(IntPtr userToken)
        {
            var lpEnvironment = IntPtr.Zero;

            try
            {
                CreateEnvironmentBlock(ref lpEnvironment, userToken, false);
            }
            catch
            { }

            return lpEnvironment;
        }

        private IntPtr GetUserTokenFromSessionInternal(int sessionId)
        {
            var userToken = IntPtr.Zero;

            try
            {
                var hImpersonationToken = IntPtr.Zero;
                var pSessionInfo = IntPtr.Zero;

                if (WTSQueryUserToken((uint)sessionId, ref hImpersonationToken) != 0)
                {
                    DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                        (int)SecurityImpersonationLevel.SecurityImpersonation, (int)TokenType.TokenPrimary,
                        ref userToken);

                    CloseHandle(hImpersonationToken);
                }
            }
            catch
            { }

            return userToken;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StartupInfo
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public enum TokenType
    {
        TokenPrimary = 1
    }

    public enum SecurityImpersonationLevel
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }
}
