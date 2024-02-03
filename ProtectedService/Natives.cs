using System;
using System.Runtime.InteropServices;

namespace ProtectedService
{
    public class Natives
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

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsProcessCritical(IntPtr hProcess, ref bool Critical);
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
