using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProtectedService
{
    public static class Services
    {
        public static (bool, int, IntPtr, IntPtr) InjectProcessToUserSessionNativeInternal(string applicationName, int sessionId)
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

                ret = Natives.DuplicateTokenEx(token, 0x10000000, ref sa, 2, 1, ref dupedToken);

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

                    ret = Natives.CreateProcessAsUser(dupedToken, applicationName, null, ref sa, ref sa, false, 0x00000400 | 0x00000010, lpEnvironment, @"C:\", ref si, out pi);

                    if (ret)
                    {
                        Natives.CloseHandle(pi.hProcess);
                        Natives.CloseHandle(pi.hThread);
                    }

                    ret = Natives.CloseHandle(dupedToken);
                }
            }
            catch
            { }

            return (ret, (int)pi.dwProcessId, lpEnvironment, pi.hProcess);
        }

        private static IntPtr CreateUserEnvironment(IntPtr userToken)
        {
            var lpEnvironment = IntPtr.Zero;

            try
            {
                Natives.CreateEnvironmentBlock(ref lpEnvironment, userToken, false);
            }
            catch
            { }

            return lpEnvironment;
        }

        private static IntPtr GetUserTokenFromSessionInternal(int sessionId)
        {
            var userToken = IntPtr.Zero;

            try
            {
                var hImpersonationToken = IntPtr.Zero;
                var pSessionInfo = IntPtr.Zero;

                if (Natives.WTSQueryUserToken((uint)sessionId, ref hImpersonationToken) != 0)
                {
                    Natives.DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                        (int)SecurityImpersonationLevel.SecurityImpersonation, (int)TokenType.TokenPrimary,
                        ref userToken);

                    Natives.CloseHandle(hImpersonationToken);
                }
            }
            catch
            { }

            return userToken;
        }

        public static void EnterCriticalModeInternal()
        {
            Process.EnterDebugMode();

            var enable = 1;

            Natives.NtSetInformationProcess(Process.GetCurrentProcess().Handle, 29, ref enable, sizeof(int));

            Process.LeaveDebugMode();
        }

        public static void ExitCriticalModeInternal()
        {
            Process.EnterDebugMode();

            var enable = 0;

            Natives.NtSetInformationProcess(Process.GetCurrentProcess().Handle, 29, ref enable, sizeof(int));

            Process.LeaveDebugMode();
        }

        public static bool CheckCriticalModeInternal()
        {
            var procStatus = false;

            if (!Natives.IsProcessCritical(Process.GetCurrentProcess().Handle, ref procStatus))
            {
                procStatus = false;
            }

            return procStatus;
        }
    }
}
