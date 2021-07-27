using System;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Globalization;
using Microsoft.VisualBasic;

namespace PacketEditor
{
    public partial class Main : Form
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        private const string AppName = "PacketEditor";

        #region Define Windows functions
        private const string KERNEL32 = "kernel32.dll";
        private const string ADVAPI32 = "advapi32.dll";

        /// <summary>
        /// Process access rights. See 
        /// <see href="https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights">
        /// Process Security and Acess Rights</see> for more information.
        /// </summary>
        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 0x001F_0FFF,
            Terminate = 0x0000_0001,
            CreateThread = 0x0000_0002,
            VMOperation = 0x0000_0008,
            VMRead = 0x0000_0010,
            VMWrite = 0x0000_0020,
            DupHandle = 0x0000_0040,
            CreateProcess = 0x0000_0080,
            SetQuota = 0x0000_0100,
            SetInformation = 0x0000_0200,
            QueryInformation = 0x0000_0400,
            SuspendResume = 0x0000_0800,
            QueryLimitedInformation = 0x0000_1000,
            Synchronize = 0x0010_0000
        }

        private enum VirtualAllocExTypes : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_RESET = 0x8_0000,
            MEM_LARGE_PAGES = 0x2000_0000,
            MEM_PHYSICAL = 0x40_0000,
            MEM_TOP_DOWN = 0x10_0000,
            MEM_WRITE_WATCH = 0x20_0000
        }

        [Flags]
        private enum AccessProtectionFlags : uint
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        private enum VirtualFreeExTypes : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        /// <summary>
        /// The type of memory allocation. See
        /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex#parameters">
        /// VirtualAllocEx function
        /// </see>
        /// for more information.
        /// </summary>
        [Flags]
        private enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x8_0000,
            RESET_UNDO = 0x100_0000,
            LARGE_PAGES = 0x2000_0000,
            PHYSICAL = 0x40_0000,
            TOP_DOWN = 0x10_0000,
            WRITE_WATCH = 0x20_0000
        }

        /// <summary>
        /// See 
        /// <see href="https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants">
        /// Memory protection constants
        /// </see> for more information.
        /// </summary>
        [Flags]
        private enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_ModifierFlag = 0x100,
            NOCACHE_ModifierFlag = 0x200,
            WRITECOMBINE_ModifierFlag = 0x400
        }

        #region Useless
        private const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private const uint STANDARD_RIGHTS_READ = 0x00020000;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_QUERY_SOURCE = 0x0010;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ADJUST_GROUPS = 0x0040;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        private const uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID;
        #endregion

        [DllImport(KERNEL32)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr
        lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport(KERNEL32)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport(KERNEL32, CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport(KERNEL32, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
           uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        // SeDebug
        [DllImport(ADVAPI32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport(ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);

        private const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        private const string SE_AUDIT_NAME = "SeAuditPrivilege";
        private const string SE_BACKUP_NAME = "SeBackupPrivilege";
        private const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
        private const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
        private const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
        private const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
        private const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
        private const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
        private const string SE_DEBUG_NAME = "SeDebugPrivilege";
        private const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
        private const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        private const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
        private const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        private const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
        private const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
        private const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
        private const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
        private const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        private const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        private const string SE_RELABEL_NAME = "SeRelabelPrivilege";
        private const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
        private const string SE_RESTORE_NAME = "SeRestorePrivilege";
        private const string SE_SECURITY_NAME = "SeSecurityPrivilege";
        private const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        private const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
        private const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
        private const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
        private const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        private const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        private const string SE_TCB_NAME = "SeTcbPrivilege";
        private const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        private const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
        private const string SE_UNDOCK_NAME = "SeUndockPrivilege";
        private const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SE_PRIVILEGE_REMOVED = 0x00000004;
        private const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        // Use this signature if you do not want the previous state
        [DllImport(ADVAPI32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           uint Zero,
           IntPtr Null1,
           IntPtr Null2);
        #endregion

        #region Fields
        private readonly string dllFullPath = Directory.GetCurrentDirectory() + @"\WSPE.dat";
        private readonly Encoding latin = Encoding.GetEncoding(28591);

        private NamedPipeServerStream pipeIn;
        private NamedPipeClientStream pipeOut;

        private Thread trdPipeRead;
        private int targetPID;
        private PipeHeader pipeMsgOut;
        private PipeHeader pipeMsgIn;
        private bool isEnabledFilter = true;
        private bool isEnabledMonitor = true;
        private bool dnsTrap;

        private Filters frmChFilters;

        private HttpListener httpListener;
        private bool isListeningHttpRequests;
        private bool firstRun = true;

        private string externalFilterPort = "8084";
        private bool isEnabledExternalFilter;

        private string processPath;
        private int processID;

        private Process procExternalFilter;
        private FrmPython formPython;
        private string reattachDelayInMs = "1000";
        private string listenerPort = "8083";
        #endregion

        #region Constructor
        public Main()
        {
            InitializeComponent();

            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
            {
                if (LookupPrivilegeValue(null, SE_DEBUG_NAME, out LUID luidSEDebugNameValue))
                {
                    TOKEN_PRIVILEGES tkpPrivileges;
                    tkpPrivileges.PrivilegeCount = 1;
                    tkpPrivileges.Luid = luidSEDebugNameValue;
                    tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                }
                CloseHandle(hToken);
            }

            mnuToolsMonitor.Checked = isEnabledMonitor;
            mnuToolsFilter.Checked = isEnabledFilter;
            tsExternalFilter.BackColor = Color.Red;
        }
        #endregion

        #region Delegates
        private delegate void DelReceiveWebRequest(HttpListenerContext context);
        private delegate void UpdateMainGridDelegate(byte[] data);
        private delegate void UpdateTreeDelegate(byte[] data);
        private delegate void ProcessExitedDelegate();
        private delegate void CurrentProcessExited();
        #endregion

        #region Event
        private event DelReceiveWebRequest ReceiveWebRequest;
        #endregion

        #region Methods
        /// <summary>
        /// Initialize NamedPipes and a thread. Call functions invoked Invoke dll files to make sure we can call functions in there.
        /// </summary>
        /// <returns><c>true</c> if the process done successfully; otherwise, <c>false</c>.</returns>
        private bool InvokeDll()
        {
            Logger.Trace("Initializing named pipes");

            pipeOut = new NamedPipeClientStream(".", "wspe.send." + targetPID.ToString("X8"), PipeDirection.Out, PipeOptions.Asynchronous);
            try
            {
                pipeIn = new NamedPipeServerStream("wspe.recv." + targetPID.ToString("X8"), PipeDirection.In, 1, PipeTransmissionMode.Message);
            }
            catch
            {
                MessageBox.Show("Cannot attach to process!\n\nA previous instance could still be " +
                    "loaded in the targets memory waiting to unload.\nTry flushing sockets by " +
                    "sending/receiving data to clear blocking sockets.",
                    "Error!",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                targetPID = 0;
                return false;
            }

            Logger.Trace("Starting calling Windows functions");

            // Inject WSPE.dat from current directory
            IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, targetPID);
            if (hProc == IntPtr.Zero)
            {
                MessageBox.Show("Cannot open process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            IntPtr ptrMem = VirtualAllocEx(hProc, (IntPtr)0, (uint)dllFullPath.Length, AllocationType.COMMIT, MemoryProtection.EXECUTE_READ);
            if (ptrMem == IntPtr.Zero)
            {
                MessageBox.Show("Cannot allocate process memory.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            byte[] dbDll = latin.GetBytes(dllFullPath);
            if (!WriteProcessMemory(hProc, ptrMem, dbDll, (uint)dbDll.Length, out _))
            {
                MessageBox.Show("Cannot write to process memory.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            IntPtr ptrLoadLib = GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA");
            CreateRemoteThread(hProc, IntPtr.Zero, 0, ptrLoadLib, ptrMem, 0, IntPtr.Zero);

            pipeIn.WaitForConnection();
            pipeOut.Connect();

            const string RegName = "PacketEditor.com";
            const string RegKey = "7007C8466C99901EF555008BF90D0C0F11C2005CE042C84B7C1E2C0050DF305647026513";

            pipeOut.Write(BitConverter.GetBytes(RegName.Length), 0, 1);
            pipeOut.Write(latin.GetBytes(RegName), 0, RegName.Length);
            pipeOut.Write(latin.GetBytes(RegKey), 0, RegKey.Length);

            Logger.Trace("Starting a new thread for reading pipe");
            trdPipeRead = new Thread(ReadPipeIn)
            {
                IsBackground = true
            };
            trdPipeRead.Start();

            return true;
        }

        /// <summary>
        /// Modify the array size to remove trailing zeros.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        private static byte[] TrimZeros(byte[] bytes)
        {
            int lastIdx = Array.FindLastIndex(bytes, b => b != 0);

            Array.Resize(ref bytes, lastIdx + 1);

            return bytes;
        }

        private static string HexStringToAddr(string s)
        {
            var r = new StringBuilder();
            for (int i = 0; i < s.Length; i += 2)
            {
                r.Append(byte.Parse(s.Substring(i, 2), NumberStyles.HexNumber).ToString());
                if (i != 6)
                    r.Append('.');
            }
            return r.ToString();
        }

        private static string BytesToAddr(byte[] bytes)
        {
            var r = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                r.Append(bytes[i]);
                if (i != 3)
                    r.Append('.');
            }
            return r.ToString();
        }

        private static string BytesToHexString(byte[] bytes)
        {
            return string.Concat(Array.ConvertAll(bytes, b => b.ToString("X2")));
        }

        private static byte[] HexStringToBytes(string s)
        {
            int newLength = s.Length / 2;
            var output = new byte[newLength];

            using (var sr = new StringReader(s))
            {
                for (int i = 0; i < newLength; i++)
                {
                    output[i] = byte.Parse(new string(new[] { (char)sr.Read(), (char)sr.Read() }), NumberStyles.HexNumber);
                }
            }

            return output;
        }

        private static Sockaddr_in AddrPortToSockAddr(string s)
        {
            int colonIdx = s.IndexOf(":", StringComparison.Ordinal);
            IPAddress ip = IPAddress.Parse(s.Substring(0, colonIdx));
            byte[] ipb = ip.GetAddressBytes();
            var sa = new Sockaddr_in
            {
                s_b1 = ipb[0],
                s_b2 = ipb[1],
                s_b3 = ipb[2],
                s_b4 = ipb[3],
                sin_port = ushort.Parse(s.Substring(colonIdx + 1, s.Length - 1 - colonIdx))
            };
            return sa;
        }

        private static Sockaddr_in HexAddrPortToSockAddr(string s)
        {
            IPAddress ip = IPAddress.Parse(
                int.Parse(s.Substring(0, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(2, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(4, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(6, 2), NumberStyles.HexNumber).ToString());
            byte[] ipb = ip.GetAddressBytes();
            var sa = new Sockaddr_in
            {
                s_b1 = ipb[0],
                s_b2 = ipb[1],
                s_b3 = ipb[2],
                s_b4 = ipb[3],
                sin_port = ushort.Parse(s.Substring(8, 4), NumberStyles.HexNumber)
            };
            return sa;
        }

        private static string GetCurrentTime()
        {
            return DateTime.Now.ToString("HH:mm:ss.fff");
        }

        /// <summary>
        /// NamedPipeClientStream.Write()
        /// </summary>
        private void WritePipe()
        {
            pipeOut.Write(Glob.RawSerializeEx(pipeMsgOut), 0, Marshal.SizeOf(pipeMsgOut));
        }

        private void UpdateMainGrid(byte[] data)
        {
            int dgridIdx = 0;
            bool changedByInternalFilter = false;
            bool changedByExternalFilter = false;
            bool tmpMonitor = isEnabledMonitor;
            var dvs = new DataGridViewCellStyle(); // TODO: may need optimization

            // If ExternalFilter is true, it will added the line later, after verify the monitor flag
            if ((!isEnabledExternalFilter || !isEnabledFilter) && tmpMonitor)
                dgridIdx = dgridMain.Rows.Add();

            // External filter run only if the filter option in menu is also checked
            if (isEnabledFilter)
            {
                #region Enabled external filter
                if (isEnabledExternalFilter)
                {
                    try
                    {
                        #region Send a post request to external filter and get the response text
                        var req = WebRequest.Create($"http://127.0.0.1:{externalFilterPort}/" +
                            $"?func={SocketInfoUtils.Msg(pipeMsgIn.function)}" +
                            $"&sockid={pipeMsgIn.sockid}");
                        //req.Proxy = WebProxy.GetDefaultProxy(); // Enable if using proxy
                        req.Method = "POST";

                        using (var writer = new StreamWriter(req.GetRequestStream()))
                        {
                            writer.WriteLine(latin.GetString(data));
                        }

                        string rspText;
                        WebResponse rsp = req.GetResponse();
                        using (var reader = new StreamReader(rsp.GetResponseStream(), Encoding.UTF8))
                        {
                            rspText = reader.ReadToEnd();
                        }
                        rsp.Close();
                        #endregion

                        // check monitor (the first) flag
                        if (rspText[0] == '0')
                            tmpMonitor = false;
                        else if (tmpMonitor)
                        {
                            dgridIdx = dgridMain.Rows.Add();
                        }

                        // check color (the second) flag
                        if (tmpMonitor)
                        {
                            if (rspText[1] == '1')
                            {
                                dvs.ForeColor = Color.Green;
                                dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                            }
                            else if (rspText[1] == '2')
                            {
                                dvs.ForeColor = Color.Red;
                                dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                            }
                        }

                        // cut the flags chars and the two new lines that finished the response
                        string subRspText = rspText.Substring(2, rspText.Length - 4);
                        if (subRspText != latin.GetString(data))
                        {
                            changedByExternalFilter = true;
                            pipeMsgOut.command = CMD.Filter;
                        }

                        data = latin.GetBytes(subRspText);
                    }
                    catch (WebException webEx)
                    {
                        MessageBox.Show(webEx.Message);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message);
                        Logger.Error(ex);
                    }
                }
                #endregion

                #region Internal filter
                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                pipeMsgOut.command = CMD.Filter;

                foreach (var row in rows)
                {
                    foreach (byte bf in (byte[])row["MsgFunction"])
                    {
                        if (bf != pipeMsgIn.function)
                        {
                            continue;
                        }

                        switch ((Action)row["MsgAction"])
                        {
                            case Action.ReplaceString:
                                if (Regex.IsMatch(latin.GetString(data), row["MsgCatch"].ToString()))
                                {
                                    try
                                    {
                                        data = latin.GetBytes(Regex.Replace(latin.GetString(data), row["MsgCatch"].ToString(), row["MsgReplace"].ToString(), RegexOptions.Multiline | RegexOptions.Compiled));
                                        changedByInternalFilter = true;
                                    }
                                    catch
                                    {
                                        if (tmpMonitor)
                                        {
                                            dvs.ForeColor = Color.Red;
                                            dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                        }
                                    }
                                }
                                break;
                            case Action.ReplaceStringHex: // Convert result to bytes of valid data, not hex
                                if (Regex.IsMatch(BytesToHexString(data), row["MsgCatch"].ToString()))
                                {
                                    try
                                    {
                                        data = HexStringToBytes(Regex.Replace(BytesToHexString(data), row["MsgCatch"].ToString(), row["MsgReplace"].ToString(), RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.IgnoreCase));
                                        changedByInternalFilter = true;
                                    }
                                    catch
                                    {
                                        if (tmpMonitor)
                                        {
                                            dvs.ForeColor = Color.Red;
                                            dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                        }
                                    }
                                }
                                break;
                            case Action.Error:
                                if (Regex.IsMatch(latin.GetString(data), row["MsgCatch"].ToString()))
                                {
                                    pipeMsgOut.extra = (int)row["MsgError"];
                                    pipeMsgOut.datasize = 0;
                                    WritePipe();
                                    if (tmpMonitor)
                                    {
                                        dvs.ForeColor = Color.DarkGray;
                                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    }
                                    goto skipfilter;
                                }
                                break;
                            case Action.ErrorHex:
                                if (Regex.IsMatch(BytesToHexString(data), row["MsgCatch"].ToString()))
                                {
                                    pipeMsgOut.extra = (int)row["MsgError"];
                                    pipeMsgOut.datasize = 0;
                                    WritePipe();
                                    if (tmpMonitor)
                                    {
                                        dvs.ForeColor = Color.DarkGray;
                                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    }
                                    goto skipfilter;
                                }
                                break;
                        }
                    }
                }
                #endregion
            }

            if (!changedByInternalFilter && !changedByExternalFilter)
            {
                pipeMsgOut.datasize = 0;
                pipeMsgOut.extra = 0; // Error
                WritePipe();
            }
            else
            {
                pipeMsgOut.datasize = data.Length;
                pipeMsgOut.extra = 0;
                WritePipe();
                pipeOut.Write(data, 0, data.Length);

                if (changedByInternalFilter && tmpMonitor)
                {
                    dvs.ForeColor = Color.Green;
                    dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                }
            }

        skipfilter:
            DataRow drsock = dsMain.Tables["sockets"].Rows.Find(pipeMsgIn.sockid);
            if (drsock != null)
            {
                if ((drsock["proto"].ToString() != string.Empty) && tmpMonitor)
                    dgridMain.Rows[dgridIdx].Cells["proto"].Value = SocketInfoUtils.ProtocolName((int)drsock["proto"]);
                drsock["lastmsg"] = pipeMsgIn.function;
            }
            else
            {
                drsock = dsMain.Tables["sockets"].NewRow();
                drsock["socket"] = pipeMsgIn.sockid;
                drsock["lastmsg"] = pipeMsgIn.function;
                dsMain.Tables["sockets"].Rows.Add(drsock);
            }

            if (tmpMonitor)
            {
                string lowerMethod = SocketInfoUtils.Msg(pipeMsgIn.function).ToLower();
                // "ecv" catch recv & Recv, "end" catch send & Send. to catch all methods (like sendto).
                if ((!lowerMethod.Contains("recv") || !showrecvRecvAllToolStripMenuItem.Checked)
                    && (!lowerMethod.Contains("send") || !showToolStripMenuItem.Checked))
                {
                    dgridMain.Rows[dgridIdx].Visible = false;
                }

                dgridMain.Rows[dgridIdx].Cells["time"].Value = GetCurrentTime();
                dgridMain.Rows[dgridIdx].Cells["socket"].Value = pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt);
                dgridMain.Rows[dgridIdx].Cells["method"].Value = SocketInfoUtils.Msg(pipeMsgIn.function);
                dgridMain.Rows[dgridIdx].Cells["rawdata"].Value = data;
                dgridMain.Rows[dgridIdx].Cells["data"].Value = latin.GetString(data);
                dgridMain.Rows[dgridIdx].Cells["size"].Value = data.Length;
            }
        }

        private void UpdateTree(byte[] data)
        {
            bool changedByInternalFilter = false;

            DataRow drsock = dsMain.Tables["sockets"].Rows.Find(pipeMsgIn.sockid);
            if (drsock != null)
            {
                drsock["lastapi"] = pipeMsgIn.function;
            }
            else if (pipeMsgIn.sockid != 0)
            {
                drsock = dsMain.Tables["sockets"].NewRow();
                drsock["socket"] = pipeMsgIn.sockid;
                drsock["lastapi"] = pipeMsgIn.function;
                dsMain.Tables["sockets"].Rows.Add(drsock);
            }

            switch (pipeMsgIn.command)
            {
                case CMD.StructData:
                    {
                        string socklr; // local or remote

                        switch (pipeMsgIn.function)
                        {
                            case Glob.FUNC_WSAACCEPT:
                            case Glob.FUNC_ACCEPT:
                                {
                                    TreeNode rootNode;
                                    if (isEnabledMonitor)
                                        rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                    else
                                        rootNode = new TreeNode();
                                    rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                                    rootNode.Nodes.Add("new socket: " + pipeMsgIn.extra.ToString(SocketInfoUtils.sockIdFmt));

                                    DataRow socketsRow = dsMain.Tables["sockets"].Rows.Find(pipeMsgIn.extra);
                                    if (socketsRow != null)
                                    {
                                        socketsRow["lastapi"] = pipeMsgIn.function;
                                    }
                                    else if (pipeMsgIn.extra != 0)
                                    {
                                        socketsRow = dsMain.Tables["sockets"].NewRow();
                                        socketsRow["socket"] = pipeMsgIn.extra;
                                        socketsRow["lastapi"] = pipeMsgIn.function;
                                        dsMain.Tables["sockets"].Rows.Add(socketsRow);
                                    }
                                }
                                goto case Glob.CONN_RECVFROM;
                            case Glob.FUNC_BIND:
                            case Glob.CONN_WSARECVFROM:
                            case Glob.CONN_RECVFROM:
                                socklr = "local";
                                goto sockaddr;
                            case Glob.FUNC_WSACONNECT:
                            case Glob.FUNC_CONNECT:
                            case Glob.CONN_WSASENDTO:
                            case Glob.CONN_SENDTO:
                                socklr = "remote";
                            sockaddr:
                                {
                                    string addrPort = "";
                                    string hexAddrPort = "";
                                    TreeNode rootNode;
                                    if (isEnabledMonitor)
                                        rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                    else
                                        rootNode = new TreeNode();
                                    rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));

                                    if (data.Length == 16) // IPv4
                                    {
                                        (data[2], data[3]) = (data[3], data[2]); // adjust port byte?

                                        Sockaddr_in sockAddr = Glob.RawDeserializeEx<Sockaddr_in>(data);
                                        IPAddress ipAddress = new IPAddress(new[] { sockAddr.s_b1, sockAddr.s_b2, sockAddr.s_b3, sockAddr.s_b4 });
                                        IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, sockAddr.sin_port);
                                        addrPort = ipEndPoint.ToString();
                                        hexAddrPort = ipAddress.MapToIPv6() + ipEndPoint.Port.ToString("X2");
                                        drsock[socklr] = addrPort;

                                        rootNode.Nodes.Add($"family: {ipEndPoint.AddressFamily} ( {Enum.GetName(typeof(AddressFamily), ipEndPoint.AddressFamily) ?? string.Empty} )");
                                        rootNode.Nodes.Add("port: " + ipEndPoint.Port);

                                        string addr = ipAddress.ToString();
                                        DataRow drDns = dsMain.Tables["dns"].Rows.Find(addr);
                                        if (drDns != null)
                                        {
                                            addr += " (" + drDns["host"] + ")";
                                        }
                                        rootNode.Nodes.Add("addr: " + addr);
                                    }
                                    else // IPv6
                                    {
                                        Sockaddr_in _ = Glob.RawDeserializeEx<Sockaddr_in>(data);
                                    }


                                    if (isEnabledFilter)
                                    {
                                        DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                        pipeMsgOut.command = CMD.Filter;

                                        foreach (var row in rows)
                                        {
                                            foreach (byte bf in (byte[])row["APIFunction"])
                                            {
                                                if (bf != pipeMsgIn.function)
                                                {
                                                    continue;
                                                }

                                                switch ((Action)row["APIAction"])
                                                {
                                                    case Action.ReplaceString:
                                                        try
                                                        {
                                                            if (Regex.IsMatch(addrPort, row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                            {
                                                                string replacedEndpoint = Regex.Replace(addrPort,
                                                                    row["APICatch"].ToString(),
                                                                    row["APIReplace"].ToString(),
                                                                    RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                                Sockaddr_in sockAddr = AddrPortToSockAddr(replacedEndpoint);
                                                                data = Glob.RawSerializeEx(sockAddr);
                                                                (data[2], data[3]) = (data[3], data[2]);
                                                                string addr = sockAddr.s_b1 + "." + sockAddr.s_b2 + "." + sockAddr.s_b3 + "." + sockAddr.s_b4;

                                                                rootNode.Nodes.Add("new port: " + sockAddr.sin_port).ForeColor = Color.Green;
                                                                rootNode.Nodes.Add("new addr: " + addr).ForeColor = Color.Green;
                                                                changedByInternalFilter = true;
                                                            }
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }

                                                        break;
                                                    case Action.ReplaceStringHex:
                                                        try
                                                        {
                                                            if (Regex.IsMatch(hexAddrPort, row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                            {
                                                                string replacedEndpoint = Regex.Replace(hexAddrPort,
                                                                    row["APICatch"].ToString(),
                                                                    row["APIReplace"].ToString(),
                                                                    RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                                Sockaddr_in sockAddr = HexAddrPortToSockAddr(replacedEndpoint);
                                                                data = Glob.RawSerializeEx(sockAddr);
                                                                (data[2], data[3]) = (data[3], data[2]);
                                                                string addr = sockAddr.s_b1 + "." + sockAddr.s_b2 + "." + sockAddr.s_b3 + "." + sockAddr.s_b4;

                                                                rootNode.Nodes.Add("new port: " + sockAddr.sin_port).ForeColor = Color.Green;
                                                                rootNode.Nodes.Add("new addr: " + addr).ForeColor = Color.Green;
                                                                changedByInternalFilter = true;
                                                            }
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }

                                                        break;
                                                    case Action.Error:
                                                        try
                                                        {
                                                            if (Regex.IsMatch(BytesToAddr(data), row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                            {
                                                                pipeMsgOut.extra = (int)row["APIError"];
                                                                pipeMsgOut.datasize = 0;
                                                                WritePipe();
                                                                rootNode.ForeColor = Color.DarkGray;
                                                                changedByInternalFilter = true;
                                                                goto skipfilterAPI2;
                                                            }
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                        break;
                                                    case Action.ErrorHex:
                                                        try
                                                        {
                                                            if (Regex.IsMatch(BytesToHexString(data), row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                            {
                                                                pipeMsgOut.extra = (int)row["APIError"];
                                                                pipeMsgOut.datasize = 0;
                                                                WritePipe();
                                                                rootNode.ForeColor = Color.DarkGray;
                                                                changedByInternalFilter = true;
                                                                goto skipfilterAPI2;
                                                            }
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                        break;
                                                }
                                            }
                                        }
                                        if (!changedByInternalFilter)
                                        {
                                            pipeMsgOut.datasize = 0;
                                            pipeMsgOut.extra = 0; // Error
                                            WritePipe();
                                            changedByInternalFilter = true;
                                        }
                                        else
                                        {
                                            pipeMsgOut.datasize = data.Length;
                                            pipeMsgOut.extra = 0;
                                            WritePipe();
                                            pipeOut.Write(data, 0, data.Length);
                                            rootNode.ForeColor = Color.Green;
                                        }
                                    }
                                }
                            skipfilterAPI2:
                                break;
                            case Glob.FUNC_WSASOCKETW_IN:
                            case Glob.FUNC_SOCKET_IN:
                                {
                                    TreeNode rootNode;
                                    if (isEnabledMonitor)
                                        rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                    else
                                        rootNode = new TreeNode();

                                    if (isEnabledFilter)
                                    {
                                        DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");

                                        pipeMsgOut.command = CMD.Filter;

                                        foreach (var row in rows)
                                        {
                                            foreach (byte bf in (byte[])row["APIFunction"])
                                            {
                                                if (bf != pipeMsgIn.function
                                                    || (Action)row["APIAction"] != Action.Error && (Action)row["APIAction"] != Action.ErrorHex)
                                                {
                                                    continue;
                                                }

                                                pipeMsgOut.extra = (int)row["APIError"];
                                                pipeMsgOut.datasize = 0;
                                                WritePipe();
                                                rootNode.ForeColor = Color.DarkGray;
                                                changedByInternalFilter = true;
                                                goto skipfilterAPI1;
                                            }
                                        }

                                        pipeMsgOut.datasize = 0;
                                        pipeMsgOut.extra = 0; // Error
                                        WritePipe();
                                        changedByInternalFilter = true;
                                    }
                                skipfilterAPI1:
                                    int addressFamily = Convert.ToInt32(data[0]);
                                    int socketType = Convert.ToInt32(data[4]);
                                    int protocolType = Convert.ToInt32(data[8]);

                                    drsock["fam"] = addressFamily;
                                    drsock["type"] = socketType;
                                    drsock["proto"] = protocolType;

                                    rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                                    rootNode.Nodes.Add($"family: {addressFamily} ({SocketInfoUtils.AddressFamilyName(addressFamily)})");
                                    rootNode.Nodes.Add($"type: {socketType} ({SocketInfoUtils.SocketTypeName(socketType)})");
                                    rootNode.Nodes.Add($"protocol: {protocolType} ({SocketInfoUtils.ProtocolName(protocolType)})");
                                }
                                break;
                        }
                    }
                    break;
                case CMD.NoData:
                    switch (pipeMsgIn.function)
                    {
                        case Glob.FUNC_WSAACCEPT:
                        case Glob.FUNC_ACCEPT:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                    rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                else
                                    rootNode = new TreeNode();

                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;
                                    foreach (var row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["APIFunction"])
                                        {
                                            if (bf != pipeMsgIn.function)
                                            {
                                                continue;
                                            }

                                            switch ((Action)row["APIAction"])
                                            {
                                                case Action.Error:
                                                case Action.ErrorHex:
                                                    pipeMsgOut.extra = (int)row["APIError"];
                                                    pipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changedByInternalFilter = true;
                                                    goto skipfilterAPI1;
                                            }
                                        }
                                    }
                                    pipeMsgOut.datasize = 0;
                                    pipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changedByInternalFilter = true;
                                }
                            skipfilterAPI1:
                                rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                                rootNode.Nodes.Add("new socket: " + pipeMsgIn.extra.ToString(SocketInfoUtils.sockIdFmt));
                                DataRow drsock2 = dsMain.Tables["sockets"].Rows.Find(pipeMsgIn.extra);
                                if (drsock2 != null)
                                {
                                    drsock2["lastapi"] = pipeMsgIn.function;
                                }
                                else if (pipeMsgIn.extra != 0)
                                {
                                    drsock2 = dsMain.Tables["sockets"].NewRow();
                                    drsock2["socket"] = pipeMsgIn.extra;
                                    drsock2["lastapi"] = pipeMsgIn.function;
                                    dsMain.Tables["sockets"].Rows.Add(drsock2);
                                }
                            }
                            break;
                        case Glob.FUNC_CLOSESOCKET:
                        case Glob.FUNC_LISTEN:
                        case Glob.FUNC_WSASENDDISCONNECT:
                        case Glob.FUNC_WSARECVDISCONNECT:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                    rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                else
                                    rootNode = new TreeNode();

                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;
                                    foreach (var row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["APIFunction"])
                                        {
                                            if (bf != pipeMsgIn.function)
                                            {
                                                continue;
                                            }

                                            switch ((Action)row["APIAction"])
                                            {
                                                case Action.Error:
                                                case Action.ErrorHex:
                                                    pipeMsgOut.extra = (int)row["APIError"];
                                                    pipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changedByInternalFilter = true;
                                                    goto skipfilterAPI2;
                                            }
                                        }
                                    }
                                    pipeMsgOut.datasize = 0;
                                    pipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changedByInternalFilter = true;
                                }
                            skipfilterAPI2:
                                rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            }
                            break;
                        case Glob.FUNC_SHUTDOWN:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                    rootNode = treeAPI.Nodes.Add(GetCurrentTime() + " " + SocketInfoUtils.Api(pipeMsgIn.function));
                                else
                                    rootNode = new TreeNode();

                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;
                                    foreach (DataRow row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["APIFunction"])
                                        {
                                            if (bf != pipeMsgIn.function
                                                || ((Action)row["APIAction"] != Action.Error && (Action)row["APIAction"] != Action.ErrorHex))
                                            {
                                                continue;
                                            }

                                            pipeMsgOut.extra = (int)row["APIError"];
                                            pipeMsgOut.datasize = 0;
                                            WritePipe();
                                            rootNode.ForeColor = Color.DarkGray;
                                            changedByInternalFilter = true;
                                            goto skipfilterAPI3;
                                        }
                                    }
                                    pipeMsgOut.datasize = 0;
                                    pipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changedByInternalFilter = true;
                                }
                            skipfilterAPI3:
                                rootNode.Nodes.Add("socket: " + pipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                                rootNode.Nodes.Add($"how: {pipeMsgIn.extra} ({SocketInfoUtils.SocketShutdownName(pipeMsgIn.extra)})");
                            }
                            break;
                    }
                    break;
                case CMD.DnsStructData:
                    switch (pipeMsgIn.function)
                    {
                        case Glob.DNS_GETHOSTBYNAME_IN:
                            {
                                TreeNode rootNode;
                                if (dnsTrap)
                                {
                                    rootNode = treeDNS.Nodes[treeDNS.Nodes.Count - 1];
                                    dnsTrap = false;
                                }
                                else
                                    rootNode = new TreeNode();

                                for (int i = 0; i < data.Length; i += 4)
                                {
                                    string addr = data[i] + "." + data[i + 1] + "." + data[i + 2] + "." + data[i + 3];
                                    rootNode.Nodes.Add("addr: " + addr);
                                    DataRow drDns = dsMain.Tables["dns"].Rows.Find(addr);
                                    if (drDns != null)
                                    {
                                        drDns["host"] = rootNode.Nodes[0].Text.Substring(6);
                                    }
                                    else
                                    {
                                        drDns = dsMain.Tables["dns"].NewRow();
                                        drDns["addr"] = addr;
                                        drDns["host"] = rootNode.Nodes[0].Text.Substring(6);
                                        dsMain.Tables["dns"].Rows.Add(drDns);
                                    }
                                }
                            }
                            break;
                        case Glob.DNS_GETHOSTBYADDR_IN:
                            if (data.Length > 4 && dnsTrap)
                            {
                                treeDNS.Nodes[treeDNS.Nodes.Count - 1].Nodes.Add("name: " + latin.GetString(data));
                                dnsTrap = false;
                            }
                            break;
                    }
                    break;
                case CMD.DnsData:
                    switch (pipeMsgIn.function)
                    {
                        case Glob.DNS_GETHOSTBYNAME_OUT:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                {
                                    rootNode = treeDNS.Nodes.Add(GetCurrentTime() + " gethostbyname()");
                                    dnsTrap = true;
                                }
                                else
                                    rootNode = new TreeNode();

                                data = TrimZeros(data);
                                rootNode.Nodes.Add("name: " + latin.GetString(data));
                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;

                                    foreach (var row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["DNSFunction"])
                                        {
                                            if (bf != pipeMsgIn.function)
                                            {
                                                continue;
                                            }

                                            switch ((Action)row["DNSAction"])
                                            {
                                                case Action.ReplaceString:
                                                    if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        try
                                                        {
                                                            string replacedString = Regex.Replace(latin.GetString(data).Replace(@"\0", ""),
                                                                row["DNSCatch"].ToString(),
                                                                row["DNSReplace"].ToString(),
                                                                RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            data = latin.GetBytes(replacedString + '\0');
                                                            rootNode.Nodes.Add("new name: " + latin.GetString(data)).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                    }
                                                    break;
                                                case Action.ReplaceStringHex:
                                                    if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        try
                                                        {
                                                            string replacedString = Regex.Replace(BytesToHexString(data),
                                                                row["DNSCatch"].ToString(),
                                                                row["DNSReplace"].ToString(),
                                                                RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            data = HexStringToBytes(replacedString + '\0');
                                                            rootNode.Nodes.Add("new name: " + latin.GetString(data)).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                    }
                                                    break;
                                                case Action.Error:
                                                    if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        pipeMsgOut.extra = (int)row["DNSError"];
                                                        pipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changedByInternalFilter = true;
                                                        goto skipfilterdns1;
                                                    }
                                                    break;
                                                case Action.ErrorHex:
                                                    if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        pipeMsgOut.extra = (int)row["DNSError"];
                                                        pipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changedByInternalFilter = true;
                                                        goto skipfilterdns1;
                                                    }
                                                    break;
                                            }
                                        }
                                    }

                                    if (!changedByInternalFilter)
                                    {
                                        pipeMsgOut.datasize = 0;
                                        pipeMsgOut.extra = 0; // Error
                                        WritePipe();
                                        changedByInternalFilter = true;
                                    }
                                    else
                                    {
                                        pipeMsgOut.datasize = data.Length;
                                        pipeMsgOut.extra = 0;
                                        WritePipe();
                                        pipeOut.Write(data, 0, data.Length);
                                        rootNode.ForeColor = Color.Green;
                                    }
                                }
                            }
                        skipfilterdns1:
                            break;
                        case Glob.DNS_GETHOSTBYADDR_OUT:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                {
                                    rootNode = treeDNS.Nodes.Add(GetCurrentTime() + " gethostbyaddr()");
                                    dnsTrap = true;
                                }
                                else
                                    rootNode = new TreeNode();

                                rootNode.Nodes.Add("addr: " + BytesToAddr(data));
                                data = TrimZeros(data);
                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;

                                    foreach (var row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["DNSFunction"])
                                        {
                                            if (bf != pipeMsgIn.function)
                                            {
                                                continue;
                                            }

                                            switch ((Action)row["DNSAction"])
                                            {
                                                case Action.ReplaceString:
                                                    try
                                                    {
                                                        if (Regex.IsMatch(BytesToAddr(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                        {
                                                            string replacedString = Regex.Replace(BytesToAddr(data),
                                                                                                  row["DNSCatch"].ToString(),
                                                                                                  row["DNSReplace"].ToString(),
                                                                                                  RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            IPAddress addy = IPAddress.Parse(replacedString);
                                                            data = addy.GetAddressBytes();
                                                            rootNode.Nodes.Add("new addr: " + addy).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }

                                                    break;
                                                case Action.ReplaceStringHex:
                                                    try
                                                    {
                                                        if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                        {
                                                            string replacedString = Regex.Replace(BytesToHexString(data),
                                                                row["DNSCatch"].ToString(),
                                                                row["DNSReplace"].ToString(),
                                                                RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            IPAddress addy = IPAddress.Parse(HexStringToAddr(replacedString));
                                                            data = addy.GetAddressBytes();
                                                            rootNode.Nodes.Add("new addr: " + addy).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }

                                                    break;
                                                case Action.Error:
                                                    try
                                                    {
                                                        if (Regex.IsMatch(BytesToAddr(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                        {
                                                            pipeMsgOut.extra = (int)row["DNSError"];
                                                            pipeMsgOut.datasize = 0;
                                                            WritePipe();
                                                            rootNode.ForeColor = Color.DarkGray;
                                                            changedByInternalFilter = true;
                                                            goto skipfilterdns2;
                                                        }
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                    break;
                                                case Action.ErrorHex:
                                                    try
                                                    {
                                                        if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                        {
                                                            pipeMsgOut.extra = (int)row["DNSError"];
                                                            pipeMsgOut.datasize = 0;
                                                            WritePipe();
                                                            rootNode.ForeColor = Color.DarkGray;
                                                            changedByInternalFilter = true;
                                                            goto skipfilterdns2;
                                                        }
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                    break;
                                            }
                                        }
                                    }

                                    if (!changedByInternalFilter)
                                    {
                                        pipeMsgOut.datasize = 0;
                                        pipeMsgOut.extra = 0; // Error
                                        WritePipe();
                                        changedByInternalFilter = true;
                                    }
                                    else
                                    {
                                        pipeMsgOut.datasize = data.Length;
                                        pipeMsgOut.extra = 0;
                                        WritePipe();
                                        pipeOut.Write(data, 0, data.Length);
                                        rootNode.ForeColor = Color.Green;
                                    }
                                }
                            }
                        skipfilterdns2:
                            break;
                        case Glob.DNS_GETHOSTNAME:
                            {
                                TreeNode rootNode;
                                if (isEnabledMonitor)
                                    rootNode = treeDNS.Nodes.Add(GetCurrentTime() + " gethostname()");
                                else
                                    rootNode = new TreeNode();

                                data = TrimZeros(data);
                                rootNode.Nodes.Add("name: " + latin.GetString(data));
                                if (isEnabledFilter)
                                {
                                    DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                    pipeMsgOut.command = CMD.Filter;

                                    foreach (var row in rows)
                                    {
                                        foreach (byte bf in (byte[])row["DNSFunction"])
                                        {
                                            if (bf != pipeMsgIn.function)
                                            {
                                                continue;
                                            }

                                            switch ((Action)row["DNSAction"])
                                            {
                                                case Action.ReplaceString:
                                                    if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        try
                                                        {
                                                            string replacedString = Regex.Replace(latin.GetString(data),
                                                                row["DNSCatch"].ToString(),
                                                                row["DNSReplace"].ToString(),
                                                                RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            data = latin.GetBytes(replacedString + '\0');
                                                            rootNode.Nodes.Add("new name: " + latin.GetString(data)).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                    }
                                                    break;
                                                case Action.ReplaceStringHex:
                                                    if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        try
                                                        {
                                                            string replacedString = Regex.Replace(BytesToHexString(data),
                                                                row["DNSCatch"].ToString(),
                                                                row["DNSReplace"].ToString(),
                                                                RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                            data = HexStringToBytes(replacedString + "\0");
                                                            rootNode.Nodes.Add("new name: " + latin.GetString(data)).ForeColor = Color.Green;
                                                            changedByInternalFilter = true;
                                                        }
                                                        catch
                                                        {
                                                            rootNode.ForeColor = Color.Red;
                                                        }
                                                    }
                                                    break;
                                                case Action.Error:
                                                    if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        pipeMsgOut.extra = (int)row["DNSError"];
                                                        pipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changedByInternalFilter = true;
                                                        goto skipfilterdns3;
                                                    }
                                                    break;
                                                case Action.ErrorHex:
                                                    if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        pipeMsgOut.extra = (int)row["DNSError"];
                                                        pipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changedByInternalFilter = true;
                                                        goto skipfilterdns3;
                                                    }
                                                    break;
                                            }
                                        }
                                    }

                                    if (!changedByInternalFilter)
                                    {
                                        pipeMsgOut.datasize = 0;
                                        pipeMsgOut.extra = 0; // Error
                                        WritePipe();
                                        changedByInternalFilter = true;
                                    }
                                    else
                                    {
                                        pipeMsgOut.datasize = data.Length;
                                        pipeMsgOut.extra = 0;
                                        WritePipe();
                                        pipeOut.Write(data, 0, data.Length);
                                        rootNode.ForeColor = Color.Green;
                                    }
                                }
                            }
                        skipfilterdns3:
                            break;
                    }
                    break;
            }

            if (isEnabledFilter && !changedByInternalFilter)
            {
                pipeMsgOut.command = CMD.Filter;
                pipeMsgOut.datasize = 0;
                pipeMsgOut.extra = 0; // Error
                WritePipe();
            }
        }

        private void ResetStateToUnattached()
        {
            pipeIn.Close();
            pipeOut.Close();
            targetPID = 0;
            Text = AppName;
            mnuFileDetach.Enabled = false;
        }

        /// <summary>
        /// Write unload dll command to the named pipe and abort the thread of reading pipe.
        /// </summary>
        private void DetachProcess()
        {
            if (pipeOut.IsConnected)
            {
                pipeMsgOut.command = CMD.UnloadDll;
                try
                {
                    WritePipe();
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }

            if (trdPipeRead.IsAlive)
            {
                trdPipeRead.Abort();
            }
        }

        private void ReadPipeIn()
        {
            byte[] pipeMsgInBuffer = new byte[14];
            byte[] zero = new byte[] { 0 };

            Delegate updateMainGrid = new UpdateMainGridDelegate(UpdateMainGrid);
            Delegate exitProc = new ProcessExitedDelegate(ResetStateToUnattached);
            Delegate updateTree = new UpdateTreeDelegate(UpdateTree);

            while (pipeIn.Read(pipeMsgInBuffer, 0, 14) != 0 || pipeIn.IsConnected)
            {
                pipeMsgIn = Glob.RawDeserializeEx<PipeHeader>(pipeMsgInBuffer);
                if (pipeMsgIn.datasize != 0)
                {
                    byte[] pipeMsgInDataBuffer = new byte[pipeMsgIn.datasize];
                    pipeIn.Read(pipeMsgInDataBuffer, 0, pipeMsgInDataBuffer.Length);

                    switch (pipeMsgIn.function)
                    {
                        case Glob.FUNC_SEND:
                        case Glob.FUNC_SENDTO:
                        case Glob.FUNC_WSASEND:
                        case Glob.FUNC_WSASENDTO:
                        case Glob.FUNC_WSASENDDISCONNECT:
                        case Glob.FUNC_RECV:
                        case Glob.FUNC_RECVFROM:
                        case Glob.FUNC_WSARECV:
                        case Glob.FUNC_WSARECVFROM:
                        case Glob.FUNC_WSARECVDISCONNECT:
                            try
                            {
                                Invoke(updateMainGrid, pipeMsgInDataBuffer);
                            }
                            catch (Exception ex)
                            {
                                Logger.Error(ex, "Invoke UpdateMainGridView failed");
                            }
                            break;
                        case Glob.CONN_RECVFROM:
                        case Glob.CONN_SENDTO:
                        case Glob.CONN_WSARECVFROM:
                        case Glob.CONN_WSASENDTO:
                        case Glob.DNS_GETHOSTBYADDR_IN:
                        case Glob.DNS_GETHOSTBYADDR_OUT:
                        case Glob.DNS_GETHOSTBYNAME_IN:
                        case Glob.DNS_GETHOSTBYNAME_OUT:
                        case Glob.DNS_GETHOSTNAME:
                        case Glob.DNS_WSAASYNCGETHOSTBYADDR_IN:
                        case Glob.DNS_WSAASYNCGETHOSTBYADDR_OUT:
                        case Glob.DNS_WSAASYNCGETHOSTBYNAME_IN:
                        case Glob.DNS_WSAASYNCGETHOSTBYNAME_OUT:
                        case Glob.FUNC_ACCEPT:
                        case Glob.FUNC_BIND:
                        case Glob.FUNC_CLOSESOCKET:
                        case Glob.FUNC_CONNECT:
                        case Glob.FUNC_GETPEERNAME:
                        case Glob.FUNC_GETSOCKNAME:
                        case Glob.FUNC_LISTEN:
                        case Glob.FUNC_SHUTDOWN:
                        case Glob.FUNC_SOCKET_IN:
                        case Glob.FUNC_SOCKET_OUT:
                        case Glob.FUNC_WSAACCEPT:
                        case Glob.FUNC_WSACLEANUP:
                        case Glob.FUNC_WSACONNECT:
                        case Glob.FUNC_WSASOCKETW_IN:
                        case Glob.FUNC_WSASOCKETW_OUT:
                            Invoke(updateTree, pipeMsgInDataBuffer);
                            break;
                    }
                }
                else
                {
                    if (pipeMsgIn.command == CMD.Init)
                    {
                        if (pipeMsgIn.function != Glob.INIT_DECRYPT)
                        {
                            continue;
                        }

                        if (pipeMsgIn.extra == 0)
                        {
                            Invoke(exitProc);
                            MessageBox.Show(this.Owner, "Invalid license.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (isEnabledMonitor)
                        {
                            pipeMsgOut.command = CMD.EnableMonitor;
                            pipeMsgOut.datasize = 0;
                            WritePipe();
                        }

                        if (isEnabledFilter)
                        {
                            pipeMsgOut.command = CMD.EnableFilter;
                            pipeMsgOut.datasize = 0;
                            WritePipe();
                        }
                    }
                    else
                    {
                        switch (pipeMsgIn.function)
                        {
                            case Glob.CONN_RECVFROM:
                            case Glob.CONN_SENDTO:
                            case Glob.CONN_WSARECVFROM:
                            case Glob.CONN_WSASENDTO:
                            case Glob.DNS_GETHOSTBYADDR_IN:
                            case Glob.DNS_GETHOSTBYADDR_OUT:
                            case Glob.DNS_GETHOSTBYNAME_IN:
                            case Glob.DNS_GETHOSTBYNAME_OUT:
                            case Glob.DNS_GETHOSTNAME:
                            case Glob.DNS_WSAASYNCGETHOSTBYADDR_IN:
                            case Glob.DNS_WSAASYNCGETHOSTBYADDR_OUT:
                            case Glob.DNS_WSAASYNCGETHOSTBYNAME_IN:
                            case Glob.DNS_WSAASYNCGETHOSTBYNAME_OUT:
                            case Glob.FUNC_ACCEPT:
                            case Glob.FUNC_BIND:
                            case Glob.FUNC_CLOSESOCKET:
                            case Glob.FUNC_CONNECT:
                            case Glob.FUNC_GETPEERNAME:
                            case Glob.FUNC_GETSOCKNAME:
                            case Glob.FUNC_LISTEN:
                            case Glob.FUNC_SHUTDOWN:
                            case Glob.FUNC_SOCKET_IN:
                            case Glob.FUNC_SOCKET_OUT:
                            case Glob.FUNC_WSAACCEPT:
                            case Glob.FUNC_WSACLEANUP:
                            case Glob.FUNC_WSACONNECT:
                            case Glob.FUNC_WSASOCKETW_IN:
                            case Glob.FUNC_WSASOCKETW_OUT:
                                Invoke(updateTree, zero);
                                break;
                            default: // Useless data call with no data
                                if (isEnabledFilter)
                                {
                                    pipeMsgOut.command = CMD.Filter;
                                    pipeMsgOut.datasize = 0;
                                    pipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                }
                                break;
                        }
                    }
                }
            }

            Invoke(exitProc);

            if (MessageBox.Show("Process Exited.\nTry to reattach?", "Alert", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes
                && !TryAttach(processID))
            {
                var currentProcExited = new CurrentProcessExited(() =>
                {
                    mnuFileDetach.Enabled = false;
                    reAttachToolStripMenuItem.Enabled = true;
                });
                Invoke(currentProcExited);
            }
        }

        private void mnuFileExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void mnuFileAttach_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                if (MessageBox.Show("You are currently attached to a process. Are you sure you would like to detach?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Exclamation,
                    MessageBoxDefaultButton.Button2) == DialogResult.No)
                {
                    return;
                }

                DetachProcess();

                ResetStateToUnattached();
            }

            var frmChAttach = new Attach();
            this.Enabled = false;
            if (this.TopMost)
                frmChAttach.TopMost = true;

            frmChAttach.ShowDialog();
            if (frmChAttach.PID != 0 && !string.IsNullOrEmpty(frmChAttach.ProcPath))
            {
                processID = frmChAttach.PID;
                processPath = frmChAttach.ProcPath;
                TryAttach(processID);
            }

            Enabled = true;
        }

        /// <summary>
        /// Check process ID and execute InvokeDll().
        /// </summary>
        /// <param name="pID">Process ID</param>
        /// <returns><c>true</c> if attach successfully; otherwise, <c>false</c>.</returns>
        private bool TryAttach(int pID)
        {
            targetPID = pID;
            if (targetPID != 0 && InvokeDll())
            {
                this.Text = AppName + " - " + processPath;
                mnuFileDetach.Enabled = true;
                reAttachToolStripMenuItem.Enabled = true;
                return true;
            }
            return false;
        }

        private void frmMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (targetPID != 0)
            {
                if (MessageBox.Show("You are currently attached to a process. Are you sure you would like to exit?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                {
                    DetachProcess();

                    pipeIn.Close();
                    pipeOut.Close();
                }
                else
                {
                    e.Cancel = true;
                    return;
                }
            }

            if (procExternalFilter != null && !procExternalFilter.HasExited)
            {
                try
                {
                    procExternalFilter.Kill();
                }
                catch (Exception ex)
                {
                    Logger.Fatal(ex);
                }
            }

            isListeningHttpRequests = false;
            if (!firstRun)
                httpListener.Close();
        }

        private void mnuFileDetach_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                DetachProcess();

                ResetStateToUnattached();

                reAttachToolStripMenuItem.Enabled = true;
            }
        }

        private void mnuToolsMonitor_CheckedChanged(object sender, EventArgs e)
        {
            if (mnuToolsMonitor.Checked)
            {
                isEnabledMonitor = true;
                dnsTrap = false;
                if (targetPID != 0)
                {
                    pipeMsgOut.command = CMD.EnableMonitor;
                    pipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
            else
            {
                isEnabledMonitor = false;
                dnsTrap = false;
                if (targetPID != 0)
                {
                    pipeMsgOut.command = CMD.DisableMonitor;
                    pipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
        }

        private void icoNotify_DoubleClick(object sender, EventArgs e)
        {
            //icoNotify.Visible = false;
            //Show();
            //WindowState = FormWindowState.Normal;
            BringToFront();
        }

        private void mnuNotifyExit_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void mnuMsgReplay_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                var frmChReplay = new ReplayEditor((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value,
                    int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier),
                    pipeOut);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
        }

        private void frmMain_Load(object sender, EventArgs e)
        {
            if (!File.Exists(dllFullPath))
            {
                Logger.Fatal("{0} not found", dllFullPath);
                this.Close();
            }
        }

        private void mnuMsgSocketSDrecv_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                pipeMsgOut.extra = (int)SocketShutdown.Receive;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketSDsend_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                pipeMsgOut.extra = (int)SocketShutdown.Send;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketSDboth_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                pipeMsgOut.extra = (int)SocketShutdown.Both;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketClose_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.function = Glob.FUNC_CLOSESOCKET;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuToolsFilter_CheckedChanged(object sender, EventArgs e)
        {
            if (mnuToolsFilter.Checked)
            {
                isEnabledFilter = true;
                if (targetPID != 0)
                {
                    pipeMsgOut.command = CMD.EnableFilter;
                    pipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
            else
            {
                isEnabledFilter = false;
                if (targetPID != 0)
                {
                    pipeMsgOut.command = CMD.DisableFilter;
                    pipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
        }

        private void mnuOptionsOntop_CheckedChanged(object sender, EventArgs e)
        {
            this.TopMost = mnuOptionsOntop.Checked;
        }

        private void frmMain_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmMain_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }

        private void mnuToolsSockets_Click(object sender, EventArgs e)
        {
            var frmChReplay = new Sockets(dsMain.Tables["sockets"], pipeOut);
            if (this.TopMost)
                frmChReplay.TopMost = true;
            frmChReplay.Show();
        }

        private void dgridMain_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.function = Glob.FUNC_SEND;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.datasize = ((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value).Length;
                WritePipe();
                try
                {
                    pipeOut.Write((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value, 0, pipeMsgOut.datasize);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }
        }

        private void mnuToolsFilters_Click(object sender, EventArgs e)
        {
            frmChFilters = new Filters(dsMain.Tables["filters"]);
            if (this.TopMost)
                frmChFilters.TopMost = true;
            frmChFilters.Show();
        }

        private void mnuInvokeFreeze_Click(object sender, EventArgs e)
        {
            const string freezeState = "Freeze";
            if (mnuInvokeFreeze.Text == freezeState)
            {
                mnuInvokeFreeze.Text = "Unfreeze";
                pipeMsgOut.command = CMD.Freeze;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
            else
            {
                mnuInvokeFreeze.Text = freezeState;
                pipeMsgOut.command = CMD.Unfreeze;
                pipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuFileOpen_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                if (MessageBox.Show("You are currently attached to a process. Are you sure you would like to detach?",
                                    "Confirm",
                                    MessageBoxButtons.YesNo,
                                    MessageBoxIcon.Warning,
                                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    return;
                }

                DetachProcess();

                ResetStateToUnattached();
            }

            using (var ofd = new OpenFileDialog
            {
                Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
                Title = "Open File",
                CheckFileExists = true,
                Multiselect = false
            })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;

                var proc = new Process
                {
                    StartInfo =
                    {
                        FileName = ofd.FileName,
                        WorkingDirectory = ofd.FileName.Substring(0, ofd.FileName.LastIndexOf('\\') + 1)
                    }
                };
                proc.Start();

                targetPID = proc.Id;
                processID = proc.Id;
                processPath = ofd.FileName;
                if (InvokeDll())
                {
                    this.Text = AppName + " - " + ofd.FileName;
                    mnuFileDetach.Enabled = true;
                }
            }
        }

        private void mnuHelpHelp_Click(object sender, EventArgs e)
        {
            Process.Start("https://appsec-labs.com/advanced-packet-editor/");
        }

        private void mnuHelpWebsite_Click(object sender, EventArgs e)
        {
            var frmChAbout = new FrmAbout();
            if (this.TopMost)
                frmChAbout.TopMost = true;
            frmChAbout.Show();
        }

        private void mnuDNSClear_Click(object sender, EventArgs e)
        {
            treeDNS.Nodes.Clear();
        }

        private void mnuAPIClear_Click(object sender, EventArgs e)
        {
            treeAPI.Nodes.Clear();
        }

        private void mnuMsgClear_Click(object sender, EventArgs e)
        {
            dgridMain.Rows.Clear();
        }

        private void mnuMsgCopyASCII_Click(object sender, EventArgs e)
        {
            var data = new StringBuilder();
            foreach (DataGridViewRow row in dgridMain.SelectedRows)
                data.Append(row.Cells["data"].Value);

            if (data.Length != 0)
                Clipboard.SetData(DataFormats.Text, data.Replace("\0", "\\0").ToString());
        }

        private void mnuMsgCopyHex_Click(object sender, EventArgs e)
        {
            var data = new StringBuilder();
            try
            {
                foreach (DataGridViewRow row in dgridMain.SelectedRows)
                    data.Append(BytesToHexString((byte[])row.Cells["rawdata"].Value));

                if (data.Length != 0)
                    Clipboard.SetData(DataFormats.Text, data.ToString());
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Copy hex data failed");
            }
        }

        private void filtersToolStripMenuItem_Click(object sender, EventArgs e)
        {
            frmChFilters.BringToFront();
        }

        private void reAttachToolStripMenuItem_Click(object sender, EventArgs e)
        {
            reattachDelayInMs = Interaction.InputBox("Delay in milliseconds (1000 = 1 second)", "Reattach delay", reattachDelayInMs);
            if (reattachDelayInMs == string.Empty || !int.TryParse(reattachDelayInMs, out int ms))
                return;

            Thread.Sleep(ms);

            if (targetPID != 0)
            {
                if (MessageBox.Show("You are currently attached to a process. Are you sure you would like to detach?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    return;
                }

                DetachProcess();

                ResetStateToUnattached();
            }

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.MainModule != null && process.MainModule.FileName == processPath) // TODO: Need to fix
                    {
                        targetPID = process.Id;
                        break;
                    }
                }
                catch (System.ComponentModel.Win32Exception w)
                {
                    Logger.Warn(w, "32 or 64 bit issue");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }

            Logger.Debug("Reattach process id: {0}", targetPID);

            if (targetPID != 0 && InvokeDll())
            {
                this.Text = AppName + " - " + processPath;
                mnuFileDetach.Enabled = true;
            }
        }

        private void injectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                var frmChReplay = new ReplayEditor(new byte[0],
                    int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier),
                    pipeOut);
                if (this.TopMost)
                    frmChReplay.TopMost = true;
                frmChReplay.Show();
            }
            else
                MessageBox.Show("You must choose the socket. You can choose from Menu->Tools->Sockets.");
        }

        private void MnuToolsProxy_Click(object sender, EventArgs e)
        {
            if (MnuToolsProxy.Checked)
            {
                isListeningHttpRequests = true;

                try
                {
                    listenerPort = Interaction.InputBox("On which port you want to listen?", "Start listen for requests", listenerPort);
                    if (listenerPort == string.Empty) // user press cancel
                        return;

                    string burpRequest = @"POST /?func=send()&sockid=0D3B HTTP/1.1
Host: 127.0.0.1:" + listenerPort + @"
Content-Length: 62
Expect: 100-continue
Connection: Keep-Alive

DATA_TO_SEND";
                    httpListener = new HttpListener();

                    if (firstRun)
                    {
                        httpListener.Prefixes.Add($"http://127.0.0.1:{listenerPort}/");

                        firstRun = false;

                        httpListener.Start();

                        isListeningHttpRequests = true;

                        new Thread(Listening).Start();
                    }
                    isListeningHttpRequests = true;

                    new FrmBurpCode(burpRequest).ShowDialog();
                }
                catch (HttpListenerException hle)
                {
                    Logger.Error(hle, "HttpListenerException Error code: {0}", hle.ErrorCode);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error occurred. Did you run it with administrator privileges?");
                    //MnuToolsProxy.Checked = false;
                    Logger.Error(ex);
                }
            }
            else
            {
                // stop the listen
                isListeningHttpRequests = false;
                //listener.Close();
            }
        }

        private void Listening()
        {
            var callback = new AsyncCallback(ListenerCallback);
            while (isListeningHttpRequests)
            {
                IAsyncResult result = httpListener.BeginGetContext(callback, httpListener);
                result.AsyncWaitHandle.WaitOne();
            }

            httpListener.Close();
        }

        private void ListenerCallback(IAsyncResult result)
        {
            if (httpListener == null)
                return;

            try
            {
                HttpListenerContext context = httpListener.EndGetContext(result); // TODO: when closing this app, httpListener will throw a disposed exception

                httpListener.BeginGetContext(ListenerCallback, httpListener);

                ReceiveWebRequest?.Invoke(context);

                ProcessRequest(context);
            }
            catch (HttpListenerException ex)
            {
                //  The I/O operation has been aborted because of either a thread exit or an application request.
                const int ErrorOperationAborted = 995;
                if (ex.ErrorCode != ErrorOperationAborted)
                {
                    Logger.Error(ex);
                    throw;
                }

                MessageBox.Show($"Swallowing HttpListenerException({ErrorOperationAborted}) Thread exit or aborted request");
            }
        }

        /// <summary>
        /// Overridable method that can be used to implement a custom handler
        /// </summary>
        /// <param name="context"></param>
        private void ProcessRequest(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;

            var sb = new StringBuilder();
            sb.AppendLine($"{request.HttpMethod} {request.RawUrl} Http/{request.ProtocolVersion}");
            string errorMsg = "";

            if (!request.HasEntityBody)
                errorMsg = "Error: Empty body";

            // Fetch sock id from request
            string socketNum;
            Regex r = new Regex(@"sockid=([0-9a-fA-F]{4,4})", RegexOptions.IgnoreCase);
            Match m = r.Match(request.Url.Query);
            if (m.Success)
            {
                socketNum = m.Groups[1].Value;
            }
            else
            {
                socketNum = null;
                errorMsg = "Error: socket id is wrong or missing";
            }

            if (int.TryParse(socketNum, NumberStyles.HexNumber, CultureInfo.CurrentCulture, out int socketId))
            {
                pipeMsgOut.sockid = socketId;
            }
            else
            {
                errorMsg = $"Error: Invalid socket ID ({socketNum})";
            }


            // Fetch function from request
            string method;
            r = new Regex(@"func=(\w+\(\))&");
            m = r.Match(request.Url.Query);
            if (m.Success)
            {
                method = m.Groups[1].Value;
            }
            else
            {
                method = null;
                errorMsg = "Error: func is wrong or missing";
            }

            string details;
            if (errorMsg != "")
                details = errorMsg;
            else
            {
                string bodyText;
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    bodyText = reader.ReadToEnd();
                }

                details = $"Socket: {socketNum}\r\n";
                details += $"Function: {method}\r\n";
                details += $"Data content type: {request.ContentType}\r\n";
                details += $"Data content length: {request.ContentLength64}\r\n";
                details += "Data:\r\n" + bodyText;

                try
                {
                    byte[] bcBytes = latin.GetBytes(bodyText);

                    pipeMsgOut.command = CMD.Inject;
                    pipeMsgOut.function = SocketInfoUtils.MsgNum(method); // Glob.FUNC_SEND;
                    pipeMsgOut.datasize = bcBytes.Length;
                    WritePipe();
                    try
                    {
                        pipeOut.Write(bcBytes, 0, pipeMsgOut.datasize);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }

                    //pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
                }
                catch (Exception ex)
                {
                    details += "\r\n" + ex.Message;
                }
            }
            // Send back the details/error
            byte[] bOutput = Encoding.UTF8.GetBytes(details);
            HttpListenerResponse response = context.Response;
            response.ContentType = "text/html";
            response.ContentLength64 = bOutput.Length;

            using (Stream outputStream = response.OutputStream)
            {
                outputStream.Write(bOutput, 0, bOutput.Length);
            }
        }

        private void showToolStripMenuItem_CheckedChanged(object sender, EventArgs e)
        {
            foreach (DataGridViewRow row in dgridMain.Rows)
            {
                if (row.Cells["method"].Value.ToString().Contains("end"))
                {
                    row.Visible = showToolStripMenuItem.Checked;
                }
            }
        }

        private void showrecvRecvAllToolStripMenuItem_CheckedChanged(object sender, EventArgs e)
        {
            foreach (DataGridViewRow row in dgridMain.Rows)
            {
                if (row.Cells["method"].Value.ToString().Contains("ecv"))
                {
                    row.Visible = showrecvRecvAllToolStripMenuItem.Checked;
                }
            }
        }

        private void dgridMain_RowsAdded(object sender, DataGridViewRowsAddedEventArgs e)
        {
            if (mnuAutoScroll.Checked && !mnuMsg.Visible)
            {
                int lastRowIndex = dgridMain.RowCount - 1;
                dgridMain.FirstDisplayedScrollingRowIndex = lastRowIndex;
                dgridMain.Refresh();
                dgridMain.CurrentCell = dgridMain.Rows[lastRowIndex].Cells[0];
                dgridMain.Rows[lastRowIndex].Selected = true;
            }
        }

        private int GetExternalFilterPort()
        {
            externalFilterPort = Interaction.InputBox("What's the port of your external filter?", "Set external filter", externalFilterPort);
            if (externalFilterPort == string.Empty || !int.TryParse(externalFilterPort, out int port))
            {
                return -1;
            }
            return port;
        }

        private void dgridMain_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                txbRecordText.Text = dgridMain.SelectedRows[0].Cells["data"].Value.ToString().Replace("\0", "\\0");
            }
        }

        private void ActivateExtenalFilter()
        {
            string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            if (!File.Exists(appDirectory + @"\scripts\external_filter_server.py"))
            {
                Logger.Fatal("{0} does not exist", appDirectory + @"\scripts\external_filter_server.py");
                return;
            }

            int port = GetExternalFilterPort();
            if (port == -1)
            {
                isEnabledExternalFilter = false;
                return;
            }

            string logFileName = CreateLogFile();
            procExternalFilter = new Process
            {
                StartInfo = new ProcessStartInfo()
                {
                    WorkingDirectory = appDirectory + @"\scripts",
                    FileName = "python.exe",
                    Arguments = $"external_filter_server.py {port} {logFileName}",
                    UseShellExecute = false,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false,
                    RedirectStandardInput = false,
                    CreateNoWindow = true
                }
            };

            if (formPython == null)
            {
                try
                {
                    procExternalFilter.Start();
                    timerPython.Start();
                    formPython = new FrmPython(logFileName);
                    formPython.Show();

                    tsExternalFilter.BackColor = Color.Green;
                    isEnabledExternalFilter = true;
                }
                catch (Exception)
                {
                    MessageBox.Show("Do you have python installed on your computer?");
                    tsExternalFilter.BackColor = Color.Red;
                }
            }
        }

        private string CreateLogFile()
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "Log.txt";
            using (FileStream fs = File.Open(path, FileMode.OpenOrCreate, FileAccess.ReadWrite))
            {
                fs.SetLength(0);
            }
            return path;
        }

        private void CloseExternalFilter()
        {
            try
            {
                if (formPython != null)
                {
                    formPython.Close();
                    formPython = null;
                }

                if (procExternalFilter != null && !procExternalFilter.HasExited)
                {
                    procExternalFilter.Kill();
                }

                tsExternalFilter.BackColor = Color.Red;
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
            }
        }

        private void toolToggleFilter_Click(object sender, EventArgs e)
        {
            var item = sender as ToolStripMenuItem;
            if (!item.Checked)
            {
                ActivateExtenalFilter();
                item.Checked = true;
            }
            else
            {
                CloseExternalFilter();
                item.Checked = false;
            }
        }

        private void MIReplay_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                pipeMsgOut.command = CMD.Inject;
                pipeMsgOut.function = Glob.FUNC_SEND;
                pipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                pipeMsgOut.datasize = ((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value).Length;
                WritePipe();
                try
                {
                    pipeOut.Write(Encoding.ASCII.GetBytes(txbRecordText.Text), 0, pipeMsgOut.datasize);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }
        }

        private void timerPython_Tick(object sender, EventArgs e)
        {
            if (procExternalFilter is null || procExternalFilter.HasExited)
            {
                tsExternalFilter.BackColor = Color.Red;
                timerPython.Stop();
            }
            else if (tsExternalFilter.BackColor != Color.Green)
            {
                tsExternalFilter.BackColor = Color.Green;
            }
        }

        private void copyForListenerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                string sockid = (string)dgridMain.SelectedRows[0].Cells["socket"].Value;
                string data = (string)dgridMain.SelectedRows[0].Cells["data"].Value;
                string method = (string)dgridMain.SelectedRows[0].Cells["method"].Value;

                string req = "POST /?func=" + method + "&sockid=" + sockid + @" HTTP/1.1
Host: 127.0.0.1:8083
Content-Length: 62
Expect: 100-continue
Connection: Keep-Alive

" + data;

                new FrmBurpCode(req).ShowDialog();
            }
        }
        #endregion

        #region Struct
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        private struct Sockaddr_in
        {
            [MarshalAs(UnmanagedType.I2)]
            public readonly short sin_family;
            public ushort sin_port;
            [MarshalAs(UnmanagedType.I1)]
            public byte s_b1;
            public byte s_b2;
            public byte s_b3;
            public byte s_b4;
            [MarshalAs(UnmanagedType.I8)]
            public readonly long sin_zero;
        }
        #endregion
    }
}
