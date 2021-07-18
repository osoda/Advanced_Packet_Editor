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
    public delegate void delReceiveWebRequest(HttpListenerContext Context);

    public partial class Main : Form
    {
        private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();
        private const string appName = "PacketEditor";

        // Vars
        NamedPipeServerStream pipeIn;
        NamedPipeClientStream pipeOut;
        readonly string dllFullPath = Directory.GetCurrentDirectory() + @"\WSPE.dat";
        Thread trdPipeRead;
        int targetPID;
        Glob.PipeHeader strPipeMsgOut;
        Glob.PipeHeader strPipeMsgIn;
        bool filter = true;
        bool monitor = true;
        bool DNStrap; // false
        readonly Encoding latin = Encoding.GetEncoding(28591);
        Filters frmChFilters;
        string reAttachPath;

        // Listen for requests
        private HttpListener httpListener;
        bool isListeningForRequests; // false
        private bool firstRun = true;

        public event delReceiveWebRequest ReceiveWebRequest;

        private string externalFilterPort = "8084";
        bool externalFilter; // false
        // Wrap the request stream with a text-based writer

        string reattacheDelayInMs = "1000";

        // Flags
        /// <summary>
        /// Process access rights.
        /// See <see href="https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights">Process Security and Acess Rights</see>
        /// for more information.
        /// </summary>
        [Flags]
        enum ProcessAccessFlags : uint
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

        enum VirtualAllocExTypes : uint
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
        enum AccessProtectionFlags : uint
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

        enum VirtualFreeExTypes : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        /// <summary>
        /// The type of memory allocation. See
        /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex#parameters">VirtualAllocEx function</see>
        /// for more information.
        /// </summary>
        [Flags]
        enum AllocationType : uint
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
        /// See <see href="https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants">Memory protection constants</see> for more information.
        /// </summary>
        [Flags]
        enum MemoryProtection : uint
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

        // DLL Imports
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr
        lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
           uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        // SeDebug
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
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
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SE_PRIVILEGE_REMOVED = 0x00000004;
        private const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           uint Zero,
           IntPtr Null1,
           IntPtr Null2);

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
        }

        // Functions
        /// <summary>
        /// Initialize NamedPipe and thread. Invoke necessary dll files to make sure we can call functions in there.
        /// </summary>
        /// <returns><c>true</c> if the process done successfully; otherwise, <c>false</c>.</returns>
        bool InvokeDLL()
        {
            logger.Trace("Invoke dlls");

            // Named Pipes
            pipeOut = new NamedPipeClientStream(".", "wspe.send." + targetPID.ToString("X8"), PipeDirection.Out, PipeOptions.Asynchronous);
            try
            {
                pipeIn = new NamedPipeServerStream("wspe.recv." + targetPID.ToString("X8"), PipeDirection.In, 1, PipeTransmissionMode.Message);
            }
            catch
            {
                MessageBox.Show("Cannot attach to process!\n\nA previous instance could still be loaded in the targets memory waiting to unload.\nTry flushing sockets by sending/receiving data to clear blocking sockets.",
                    "Error!",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                targetPID = 0;
                return false;
            }

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

            byte[] dbDLL = latin.GetBytes(dllFullPath);
            if (!WriteProcessMemory(hProc, ptrMem, dbDLL, (uint)dbDLL.Length, out int ipTmp))
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

            trdPipeRead = new Thread(new ThreadStart(PipeRead))
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
        byte[] TrimZeros(byte[] bytes)
        {
            int lastIdx = Array.FindLastIndex(bytes, b => b != 0);

            Array.Resize(ref bytes, lastIdx + 1);

            return bytes;
        }

        string HexStringToAddr(string s)
        {
            string r = "";
            // TODO: optimize for loop
            for (int i = 0; i < s.Length; i += 2)
            {
                r += byte.Parse(s.Substring(i, 2), NumberStyles.HexNumber).ToString();
                if (i != 6)
                    r += ".";
            }
            return r;
        }

        string BytesToAddr(byte[] bytes)
        {
            string r = "";
            for (int i = 0; i < bytes.Length; i++)
            {
                r += bytes[i].ToString();
                if (i != 3)
                    r += ".";
            }
            return r;
        }

        string BytesToHexString(byte[] bytes)
        {
            return String.Concat(Array.ConvertAll(bytes, b => b.ToString("X2")));
        }

        byte[] HexStringToBytes(string s)
        {
            int newLength = s.Length / 2;
            var output = new byte[newLength];

            using (var sr = new StringReader(s))
            {
                for (int i = 0; i < newLength; i++)
                {
                    output[i] = byte.Parse(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), NumberStyles.HexNumber);
                }
            }

            return output;
        }

        Glob.Sockaddr_in AddrPortToSockAddr(string s)
        {
            int colonIdx = s.IndexOf(":");
            IPAddress ip = IPAddress.Parse(s.Substring(0, colonIdx));
            byte[] ipb = ip.GetAddressBytes();
            Glob.Sockaddr_in sa = new Glob.Sockaddr_in
            {
                s_b1 = ipb[0],
                s_b2 = ipb[1],
                s_b3 = ipb[2],
                s_b4 = ipb[3],
                sin_port = ushort.Parse(s.Substring(colonIdx + 1, s.Length - 1 - colonIdx))
            };
            return sa;
        }

        Glob.Sockaddr_in HexAddrPortToSockAddr(string s)
        {
            IPAddress ip = IPAddress.Parse(
                int.Parse(s.Substring(0, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(2, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(4, 2), NumberStyles.HexNumber).ToString() + "."
                + int.Parse(s.Substring(6, 2), NumberStyles.HexNumber).ToString());
            byte[] ipb = ip.GetAddressBytes();
            Glob.Sockaddr_in sa = new Glob.Sockaddr_in
            {
                s_b1 = ipb[0],
                s_b2 = ipb[1],
                s_b3 = ipb[2],
                s_b4 = ipb[3],
                sin_port = ushort.Parse(s.Substring(8, 4), NumberStyles.HexNumber)
            };
            return sa;
        }

        /// <summary>
        /// NamedPipeClientStream.Write()
        /// </summary>
        void WritePipe()
        {
            pipeOut.Write(Glob.RawSerializeEx(strPipeMsgOut), 0, Marshal.SizeOf(strPipeMsgOut));
        }

        void UpdateMainGrid(byte[] data)
        {
            int dgridIdx = 0;
            bool changed_by_internal_filter = false;
            bool changed_by_external_filter = false;
            //backup because it will changed later
            bool monitor_original = monitor; // TODO: need optimal
            DataGridViewCellStyle dvs = new DataGridViewCellStyle();

            // If ExternalFilter is true, it will added the line later, after verify the monitor flag
            if ((!externalFilter || !filter) && monitor)
                dgridIdx = dgridMain.Rows.Add();

            // External filter run only if also the filter option in menu is true
            if (filter && externalFilter)
            {
                try
                {
                    // send to external filter
                    WebRequest req = WebRequest.Create($"http://127.0.0.1:{externalFilterPort}/?func={SocketInfoUtils.Msg(strPipeMsgIn.function)}&sockid={strPipeMsgIn.sockid}");
                    //req.Proxy = WebProxy.GetDefaultProxy(); // Enable if using proxy
                    req.Method = "POST";
                    // Write the text into the stream
                    using (var writer = new StreamWriter(req.GetRequestStream()))
                    {
                        writer.WriteLine(latin.GetString(data));
                    }


                    string rspText;
                    // Send the data to the webserver and read the response
                    WebResponse rsp = req.GetResponse();
                    using (var reader = new StreamReader(rsp.GetResponseStream(), Encoding.UTF8))
                    {
                        rspText = reader.ReadToEnd();
                    }
                    rsp.Close();

                    // check monitor (the first) flag
                    if (rspText[0] == '0')// || !monitor)
                        monitor = false;
                    else if (monitor)
                    {
                        //monitor = true;
                        dgridIdx = dgridMain.Rows.Add();
                    }

                    // check color (the second) flag
                    if (monitor)
                    {
                        switch (rspText[1])
                        {
                            case '1':
                                dvs.ForeColor = Color.Green;
                                break;
                            case '2':
                                dvs.ForeColor = Color.Red;
                                break;
                        }
                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                    }

                    // cut the falgs chars and the two new lines that finished the response
                    string subRspText = rspText.Substring(2, rspText.Length - 4);
                    if (subRspText != latin.GetString(data))
                    {
                        changed_by_external_filter = true;
                        strPipeMsgOut.command = Glob.CMD_FILTER;
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
                    logger.Error(ex, "Update main grid view exception");
                }
            }

            // Internal filter
            if (filter)
            {
                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                strPipeMsgOut.command = Glob.CMD_FILTER;

                foreach (var row in rows)
                {
                    foreach (byte bf in (byte[])row["MsgFunction"])
                    {
                        if (bf != strPipeMsgIn.function)
                        {
                            continue;
                        }

                        switch ((byte)row["MsgAction"])
                        {
                            case Glob.ActionReplaceString:
                                if (Regex.IsMatch(latin.GetString(data), row["MsgCatch"].ToString()))
                                {
                                    try
                                    {
                                        data = latin.GetBytes(Regex.Replace(latin.GetString(data), row["MsgCatch"].ToString(), row["MsgReplace"].ToString(), RegexOptions.Multiline | RegexOptions.Compiled));
                                        changed_by_internal_filter = true;
                                    }
                                    catch
                                    {
                                        dvs.ForeColor = Color.Red;
                                        if (monitor)
                                            dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    }
                                }
                                break;
                            case Glob.ActionReplaceStringH: // Convert result to bytes of valid data, not hex
                                if (Regex.IsMatch(BytesToHexString(data), row["MsgCatch"].ToString()))
                                {
                                    try
                                    {
                                        data = HexStringToBytes(Regex.Replace(BytesToHexString(data), row["MsgCatch"].ToString(), row["MsgReplace"].ToString(), RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.IgnoreCase));
                                        changed_by_internal_filter = true;
                                    }
                                    catch
                                    {
                                        dvs.ForeColor = Color.Red;
                                        if (monitor)
                                            dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    }
                                }
                                break;
                            case Glob.ActionError:
                                if (Regex.IsMatch(latin.GetString(data), row["MsgCatch"].ToString()))
                                {
                                    strPipeMsgOut.extra = (int)row["MsgError"];
                                    strPipeMsgOut.datasize = 0;
                                    WritePipe();
                                    dvs.ForeColor = Color.DarkGray;
                                    if (monitor)
                                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    goto skipfilter;
                                }
                                break;
                            case Glob.ActionErrorH:
                                if (Regex.IsMatch(BytesToHexString(data), row["MsgCatch"].ToString()))
                                {
                                    strPipeMsgOut.extra = (int)row["MsgError"];
                                    strPipeMsgOut.datasize = 0;
                                    WritePipe();
                                    dvs.ForeColor = Color.DarkGray;
                                    if (monitor)
                                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                                    goto skipfilter;
                                }
                                break;
                        }
                    }
                }
            }

            if (!changed_by_internal_filter && !changed_by_external_filter)
            {
                strPipeMsgOut.datasize = 0;
                strPipeMsgOut.extra = 0; // Error
                WritePipe();
            }
            else
            {
                strPipeMsgOut.datasize = data.Length;
                strPipeMsgOut.extra = 0;
                WritePipe();
                pipeOut.Write(data, 0, data.Length);
                if (changed_by_internal_filter)
                {
                    dvs.ForeColor = Color.Green;
                    if (monitor)
                        dgridMain.Rows[dgridIdx].Cells["data"].Style = dvs;
                }
            }

        skipfilter:
            DataRow drsock = dsMain.Tables["sockets"].Rows.Find(strPipeMsgIn.sockid);
            if (drsock != null)
            {
                if ((drsock["proto"].ToString() != string.Empty) && monitor)
                    dgridMain.Rows[dgridIdx].Cells["proto"].Value = SocketInfoUtils.ProtocolName((int)drsock["proto"]);
                drsock["lastmsg"] = strPipeMsgIn.function;
            }
            else
            {
                drsock = dsMain.Tables["sockets"].NewRow();
                drsock["socket"] = strPipeMsgIn.sockid;
                drsock["lastmsg"] = strPipeMsgIn.function;
                dsMain.Tables["sockets"].Rows.Add(drsock);
            }

            if (monitor)
            {
                string method = SocketInfoUtils.Msg(strPipeMsgIn.function).ToLower();
                // "ecv" catch recv & Recv, "end" catch send & Send. to catch all methods (like sendto).
                if (method.Contains("recv") && showrecvRecvAllToolStripMenuItem.Checked
                    || method.Contains("send") && showToolStripMenuItem.Checked)
                {
                }
                else
                {
                    dgridMain.Rows[dgridIdx].Visible = false;
                }

                dgridMain.Rows[dgridIdx].Cells["time"].Value = DateTime.Now.ToLongTimeString();
                dgridMain.Rows[dgridIdx].Cells["socket"].Value = strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt);
                dgridMain.Rows[dgridIdx].Cells["method"].Value = SocketInfoUtils.Msg(strPipeMsgIn.function);
                dgridMain.Rows[dgridIdx].Cells["rawdata"].Value = data;
                dgridMain.Rows[dgridIdx].Cells["data"].Value = latin.GetString(data);
                dgridMain.Rows[dgridIdx].Cells["size"].Value = data.Length;
            }

            monitor = monitor_original;
        }

        void UpdateTree(byte[] data)
        {
            TreeNode rootNode;
            Glob.Sockaddr_in sockAddr;
            bool changed_by_internal_filter = false;
            string addr;

            DataRow drsock = dsMain.Tables["sockets"].Rows.Find(strPipeMsgIn.sockid);

            if (drsock != null)
            {
                drsock["lastapi"] = strPipeMsgIn.function;
            }
            else if (strPipeMsgIn.sockid != 0)
            {
                drsock = dsMain.Tables["sockets"].NewRow();
                drsock["socket"] = strPipeMsgIn.sockid;
                drsock["lastapi"] = strPipeMsgIn.function;
                dsMain.Tables["sockets"].Rows.Add(drsock);
            }

            //Glob.RawDeserializeEx();
            switch (strPipeMsgIn.command)
            {
                case Glob.CMD_STRUCTDATA:
                    string socklr; // local or remote
                    switch (strPipeMsgIn.function)
                    {
                        case Glob.FUNC_WSAACCEPT:
                        case Glob.FUNC_ACCEPT:
                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();
                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            rootNode.Nodes.Add("new socket: " + strPipeMsgIn.extra.ToString(SocketInfoUtils.sockIdFmt));

                            DataRow socketsRow = dsMain.Tables["sockets"].Rows.Find(strPipeMsgIn.extra);
                            if (socketsRow != null)
                            {
                                socketsRow["lastapi"] = strPipeMsgIn.function;
                            }
                            else if (strPipeMsgIn.extra != 0)
                            {
                                socketsRow = dsMain.Tables["sockets"].NewRow();
                                socketsRow["socket"] = strPipeMsgIn.extra;
                                socketsRow["lastapi"] = strPipeMsgIn.function;
                                dsMain.Tables["sockets"].Rows.Add(socketsRow);
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
                            string addrPort = "";
                            string hexAddrPort = "";

                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();
                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));

                            if (data.Length == 16) // IPv4
                            {
                                (data[2], data[3]) = (data[3], data[2]); // adjust port byte?

                                sockAddr = Glob.RawDeserializeEx<Glob.Sockaddr_in>(data);
                                IPAddress ipAddress = new IPAddress(new byte[] { sockAddr.s_b1, sockAddr.s_b2, sockAddr.s_b3, sockAddr.s_b4 });
                                IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, sockAddr.sin_port);
                                addrPort = ipEndPoint.ToString();
                                hexAddrPort = ipAddress.MapToIPv6().ToString() + ipEndPoint.Port.ToString("X2");
                                //addrPort = sockAddr.s_b1.ToString() + "." + sockAddr.s_b2.ToString() + "." + sockAddr.s_b3.ToString() + "." + sockAddr.s_b4.ToString() + ":" + sockAddr.sin_port.ToString();
                                //hexAddrPort = sockAddr.s_b1.ToString("X2") + sockAddr.s_b2.ToString("X2") + sockAddr.s_b3.ToString("X2") + sockAddr.s_b4.ToString("X2") + sockAddr.sin_port.ToString("X4");
                                drsock[socklr] = addrPort;
                                //if ((sockAddr.sin_family >= 0) && (sockAddr.sin_family <= SocketInfoUtils.afamily.Length - 1))
                                //{
                                //    rootnode.Nodes.Add("family: " + sockAddr.sin_family.ToString() + " (" + SocketInfoUtils.afamily[sockAddr.sin_family] + ")");
                                //}
                                //else
                                //{
                                //    rootnode.Nodes.Add("family: " + sockAddr.sin_family.ToString());
                                //}
                                rootNode.Nodes.Add($"family: {ipEndPoint.AddressFamily} ( {Enum.GetName(typeof(AddressFamily), ipEndPoint.AddressFamily) ?? string.Empty} )");
                                rootNode.Nodes.Add("port: " + ipEndPoint.Port.ToString());
                                //addr = sockAddr.s_b1.ToString() + "." + sockAddr.s_b2.ToString() + "." + sockAddr.s_b3.ToString() + "." + sockAddr.s_b4.ToString();
                                addr = ipAddress.ToString();
                                drsock = dsMain.Tables["dns"].Rows.Find(addr);
                                if (drsock != null)
                                {
                                    addr += " (" + drsock["host"] + ")";
                                }
                                rootNode.Nodes.Add("addr: " + addr);
                            }
                            else
                            {
                                // IPv6
                                sockAddr = Glob.RawDeserializeEx<Glob.Sockaddr_in>(data);
                            }


                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;

                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["APIFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["APIAction"])
                                        {
                                            case Glob.ActionReplaceString:
                                                try
                                                {
                                                    if (Regex.IsMatch(addrPort, row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        string replacedEndpoint = Regex.Replace(addrPort,
                                                            row["APICatch"].ToString(),
                                                            row["APIReplace"].ToString(),
                                                            RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                        sockAddr = AddrPortToSockAddr(replacedEndpoint);
                                                        data = Glob.RawSerializeEx(sockAddr);
                                                        (data[2], data[3]) = (data[3], data[2]);
                                                        addr = sockAddr.s_b1.ToString() + "." + sockAddr.s_b2.ToString() + "." + sockAddr.s_b3.ToString() + "." + sockAddr.s_b4.ToString();

                                                        rootNode.Nodes.Add("new port: " + sockAddr.sin_port.ToString()).ForeColor = Color.Green;
                                                        rootNode.Nodes.Add("new addr: " + addr).ForeColor = Color.Green;
                                                        changed_by_internal_filter = true;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }

                                                break;
                                            case Glob.ActionReplaceStringH:
                                                try
                                                {
                                                    if (Regex.IsMatch(hexAddrPort, row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        string replacedEndpoint = Regex.Replace(hexAddrPort,
                                                            row["APICatch"].ToString(),
                                                            row["APIReplace"].ToString(),
                                                            RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                                                        sockAddr = HexAddrPortToSockAddr(replacedEndpoint);
                                                        data = Glob.RawSerializeEx(sockAddr);
                                                        (data[2], data[3]) = (data[3], data[2]);
                                                        addr = sockAddr.s_b1.ToString() + "." + sockAddr.s_b2.ToString() + "." + sockAddr.s_b3.ToString() + "." + sockAddr.s_b4.ToString();

                                                        rootNode.Nodes.Add("new port: " + sockAddr.sin_port.ToString()).ForeColor = Color.Green;
                                                        rootNode.Nodes.Add("new addr: " + addr).ForeColor = Color.Green;
                                                        changed_by_internal_filter = true;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }

                                                break;
                                            case Glob.ActionError:
                                                try
                                                {
                                                    if (Regex.IsMatch(BytesToAddr(data), row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        strPipeMsgOut.extra = (int)row["APIError"];
                                                        strPipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changed_by_internal_filter = true;
                                                        goto skipfilterAPI2;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }
                                                break;
                                            case Glob.ActionErrorH:
                                                try
                                                {
                                                    if (Regex.IsMatch(BytesToHexString(data), row["APICatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        strPipeMsgOut.extra = (int)row["APIError"];
                                                        strPipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changed_by_internal_filter = true;
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
                                if (!changed_by_internal_filter)
                                {
                                    strPipeMsgOut.datasize = 0;
                                    strPipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changed_by_internal_filter = true;
                                }
                                else
                                {
                                    strPipeMsgOut.datasize = data.Length;
                                    strPipeMsgOut.extra = 0;
                                    WritePipe();
                                    pipeOut.Write(data, 0, data.Length);
                                    rootNode.ForeColor = Color.Green;
                                }
                            }
                        skipfilterAPI2:
                            break;
                        case Glob.FUNC_WSASOCKETW_IN:
                        case Glob.FUNC_SOCKET_IN:
                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();

                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;
                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["APIFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["APIAction"])
                                        {
                                            case Glob.ActionError:
                                            case Glob.ActionErrorH:
                                                strPipeMsgOut.extra = (int)row["APIError"];
                                                strPipeMsgOut.datasize = 0;
                                                WritePipe();
                                                rootNode.ForeColor = Color.DarkGray;
                                                changed_by_internal_filter = true;
                                                goto skipfilterAPI1;
                                        }
                                    }
                                }
                                strPipeMsgOut.datasize = 0;
                                strPipeMsgOut.extra = 0; // Error
                                WritePipe();
                                changed_by_internal_filter = true;
                            }
                        skipfilterAPI1:
                            int addressFamily = Convert.ToInt32(data[0]);
                            int socketType = Convert.ToInt32(data[4]);
                            int protocolType = Convert.ToInt32(data[8]);

                            drsock["fam"] = addressFamily;
                            drsock["type"] = socketType;
                            drsock["proto"] = protocolType;

                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            rootNode.Nodes.Add($"family: {addressFamily} ({SocketInfoUtils.AddressFamilyName(addressFamily)})");
                            rootNode.Nodes.Add($"type: {socketType} ({SocketInfoUtils.SocketTypeName(socketType)})");
                            rootNode.Nodes.Add($"protocol: {protocolType} ({SocketInfoUtils.ProtocolName(protocolType)})");
                            break;
                            //case Glob.FUNC_WSASOCKETW_OUT:
                            //case Glob.FUNC_SOCKET_OUT:
                            //    break;
                    }
                    break;
                case Glob.CMD_NODATA:
                    switch (strPipeMsgIn.function)
                    {
                        case Glob.FUNC_WSAACCEPT:
                        case Glob.FUNC_ACCEPT:
                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();

                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;
                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["APIFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["APIAction"])
                                        {
                                            case Glob.ActionError:
                                            case Glob.ActionErrorH:
                                                strPipeMsgOut.extra = (int)row["APIError"];
                                                strPipeMsgOut.datasize = 0;
                                                WritePipe();
                                                rootNode.ForeColor = Color.DarkGray;
                                                changed_by_internal_filter = true;
                                                goto skipfilterAPI1;
                                        }
                                    }
                                }
                                strPipeMsgOut.datasize = 0;
                                strPipeMsgOut.extra = 0; // Error
                                WritePipe();
                                changed_by_internal_filter = true;
                            }
                        skipfilterAPI1:
                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            rootNode.Nodes.Add("new socket: " + strPipeMsgIn.extra.ToString(SocketInfoUtils.sockIdFmt));
                            DataRow drsock2 = dsMain.Tables["sockets"].Rows.Find(strPipeMsgIn.extra);
                            if (drsock2 != null)
                            {
                                drsock2["lastapi"] = strPipeMsgIn.function;
                            }
                            else if (strPipeMsgIn.extra != 0)
                            {
                                drsock2 = dsMain.Tables["sockets"].NewRow();
                                drsock2["socket"] = strPipeMsgIn.extra;
                                drsock2["lastapi"] = strPipeMsgIn.function;
                                dsMain.Tables["sockets"].Rows.Add(drsock2);
                            }
                            break;
                        case Glob.FUNC_CLOSESOCKET:
                        case Glob.FUNC_LISTEN:
                        case Glob.FUNC_WSASENDDISCONNECT:
                        case Glob.FUNC_WSARECVDISCONNECT:
                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();

                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;
                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["APIFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["APIAction"])
                                        {
                                            case Glob.ActionError:
                                            case Glob.ActionErrorH:
                                                strPipeMsgOut.extra = (int)row["APIError"];
                                                strPipeMsgOut.datasize = 0;
                                                WritePipe();
                                                rootNode.ForeColor = Color.DarkGray;
                                                changed_by_internal_filter = true;
                                                goto skipfilterAPI2;
                                        }
                                    }
                                }
                                strPipeMsgOut.datasize = 0;
                                strPipeMsgOut.extra = 0; // Error
                                WritePipe();
                                changed_by_internal_filter = true;
                            }
                        skipfilterAPI2:
                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            break;
                        case Glob.FUNC_SHUTDOWN:
                            if (monitor)
                                rootNode = treeAPI.Nodes.Add(DateTime.Now.ToLongTimeString() + " " + SocketInfoUtils.Api(strPipeMsgIn.function));
                            else
                                rootNode = new TreeNode();

                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;
                                foreach (DataRow row in rows)
                                {
                                    foreach (byte bf in (byte[])row["APIFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["APIAction"])
                                        {
                                            case Glob.ActionError:
                                            case Glob.ActionErrorH:
                                                strPipeMsgOut.extra = (int)row["APIError"];
                                                strPipeMsgOut.datasize = 0;
                                                WritePipe();
                                                rootNode.ForeColor = Color.DarkGray;
                                                changed_by_internal_filter = true;
                                                goto skipfilterAPI3;
                                        }
                                    }
                                }
                                strPipeMsgOut.datasize = 0;
                                strPipeMsgOut.extra = 0; // Error
                                WritePipe();
                                changed_by_internal_filter = true;
                            }
                        skipfilterAPI3:
                            rootNode.Nodes.Add("socket: " + strPipeMsgIn.sockid.ToString(SocketInfoUtils.sockIdFmt));
                            rootNode.Nodes.Add($"how: {strPipeMsgIn.extra} ({SocketInfoUtils.SocketShutdownName(strPipeMsgIn.extra)})");
                            //if ((strPipeMsgIn.extra >= 0) && (strPipeMsgIn.extra <= SocketInfoUtils.sdhow.Length - 1))
                            //{
                            //    rootNode.Nodes.Add("how: " + strPipeMsgIn.extra.ToString() + " (" + SocketInfoUtils.sdhow[strPipeMsgIn.extra] + ")");
                            //}
                            //else
                            //{
                            //    rootNode.Nodes.Add("how: " + strPipeMsgIn.extra.ToString());
                            //}
                            break;
                    }
                    break;
                case Glob.CMD_DNS_STRUCTDATA:
                    switch (strPipeMsgIn.function)
                    {
                        case Glob.DNS_GETHOSTBYNAME_IN:
                            if (DNStrap)
                            {
                                rootNode = treeDNS.Nodes[treeDNS.Nodes.Count - 1];
                                DNStrap = false;
                            }
                            else
                                rootNode = new TreeNode();

                            for (int i = 0; i < data.Length; i += 4)
                            {
                                addr = data[i].ToString() + "." + data[i + 1].ToString() + "." + data[i + 2].ToString() + "." + data[i + 3].ToString();
                                rootNode.Nodes.Add("addr: " + addr);
                                drsock = dsMain.Tables["dns"].Rows.Find(addr);
                                if (drsock != null)
                                {
                                    drsock["host"] = rootNode.Nodes[0].Text.ToString().Substring(6);
                                }
                                else
                                {
                                    drsock = dsMain.Tables["dns"].NewRow();
                                    drsock["addr"] = addr;
                                    drsock["host"] = rootNode.Nodes[0].Text.ToString().Substring(6);
                                    dsMain.Tables["dns"].Rows.Add(drsock);
                                }
                            }
                            break;
                        case Glob.DNS_GETHOSTBYADDR_IN:
                            if (data.Length > 4 && DNStrap)
                            {
                                treeDNS.Nodes[treeDNS.Nodes.Count - 1].Nodes.Add("name: " + latin.GetString(data));
                                DNStrap = false;
                            }
                            break;
                    }
                    break;
                case Glob.CMD_DNS_DATA:
                    switch (strPipeMsgIn.function)
                    {
                        case Glob.DNS_GETHOSTBYNAME_OUT:
                            if (monitor)
                            {
                                rootNode = treeDNS.Nodes.Add(DateTime.Now.ToLongTimeString() + " gethostbyname()");
                                DNStrap = true;
                            }
                            else
                                rootNode = new TreeNode();

                            data = TrimZeros(data);
                            rootNode.Nodes.Add("name: " + latin.GetString(data));
                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;

                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["DNSFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["DNSAction"])
                                        {
                                            case Glob.ActionReplaceString:
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
                                                        changed_by_internal_filter = true;
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                }
                                                break;
                                            case Glob.ActionReplaceStringH:
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
                                                        changed_by_internal_filter = true;
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                }
                                                break;
                                            case Glob.ActionError:
                                                if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                {
                                                    strPipeMsgOut.extra = (int)row["DNSError"];
                                                    strPipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changed_by_internal_filter = true;
                                                    goto skipfilterdns1;
                                                }
                                                break;
                                            case Glob.ActionErrorH:
                                                if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                {
                                                    strPipeMsgOut.extra = (int)row["DNSError"];
                                                    strPipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changed_by_internal_filter = true;
                                                    goto skipfilterdns1;
                                                }
                                                break;
                                        }
                                    }
                                }

                                if (!changed_by_internal_filter)
                                {
                                    strPipeMsgOut.datasize = 0;
                                    strPipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changed_by_internal_filter = true;
                                }
                                else
                                {
                                    strPipeMsgOut.datasize = data.Length;
                                    strPipeMsgOut.extra = 0;
                                    WritePipe();
                                    pipeOut.Write(data, 0, data.Length);
                                    rootNode.ForeColor = Color.Green;
                                }
                            }
                        skipfilterdns1:
                            break;
                        case Glob.DNS_GETHOSTBYADDR_OUT:
                            if (monitor)
                            {
                                rootNode = treeDNS.Nodes.Add(DateTime.Now.ToLongTimeString() + " gethostbyaddr()");
                                DNStrap = true;
                            }
                            else
                                rootNode = new TreeNode();

                            rootNode.Nodes.Add("addr: " + BytesToAddr(data));
                            data = TrimZeros(data);
                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;

                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["DNSFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["DNSAction"])
                                        {
                                            case Glob.ActionReplaceString:
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
                                                        rootNode.Nodes.Add("new addr: " + addy.ToString()).ForeColor = Color.Green;
                                                        changed_by_internal_filter = true;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }

                                                break;
                                            case Glob.ActionReplaceStringH:
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
                                                        rootNode.Nodes.Add("new addr: " + addy.ToString()).ForeColor = Color.Green;
                                                        changed_by_internal_filter = true;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }

                                                break;
                                            case Glob.ActionError:
                                                try
                                                {
                                                    if (Regex.IsMatch(BytesToAddr(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        strPipeMsgOut.extra = (int)row["DNSError"];
                                                        strPipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changed_by_internal_filter = true;
                                                        goto skipfilterdns2;
                                                    }
                                                }
                                                catch
                                                {
                                                    rootNode.ForeColor = Color.Red;
                                                }
                                                break;
                                            case Glob.ActionErrorH:
                                                try
                                                {
                                                    if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                    {
                                                        strPipeMsgOut.extra = (int)row["DNSError"];
                                                        strPipeMsgOut.datasize = 0;
                                                        WritePipe();
                                                        rootNode.ForeColor = Color.DarkGray;
                                                        changed_by_internal_filter = true;
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

                                if (!changed_by_internal_filter)
                                {
                                    strPipeMsgOut.datasize = 0;
                                    strPipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changed_by_internal_filter = true;
                                }
                                else
                                {
                                    strPipeMsgOut.datasize = data.Length;
                                    strPipeMsgOut.extra = 0;
                                    WritePipe();
                                    pipeOut.Write(data, 0, data.Length);
                                    rootNode.ForeColor = Color.Green;
                                }
                            }
                        skipfilterdns2:
                            break;
                        case Glob.DNS_GETHOSTNAME:
                            if (monitor)
                                rootNode = treeDNS.Nodes.Add(DateTime.Now.ToLongTimeString() + " gethostname()");
                            else
                                rootNode = new TreeNode();

                            data = TrimZeros(data);
                            rootNode.Nodes.Add("name: " + latin.GetString(data));
                            if (filter)
                            {
                                DataRow[] rows = dsMain.Tables["filters"].Select("enabled = true");
                                strPipeMsgOut.command = Glob.CMD_FILTER;

                                foreach (var row in rows)
                                {
                                    foreach (byte bf in (byte[])row["DNSFunction"])
                                    {
                                        if (bf != strPipeMsgIn.function)
                                        {
                                            continue;
                                        }

                                        switch ((byte)row["DNSAction"])
                                        {
                                            case Glob.ActionReplaceString:
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
                                                        changed_by_internal_filter = true;
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                }
                                                break;
                                            case Glob.ActionReplaceStringH:
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
                                                        changed_by_internal_filter = true;
                                                    }
                                                    catch
                                                    {
                                                        rootNode.ForeColor = Color.Red;
                                                    }
                                                }
                                                break;
                                            case Glob.ActionError:
                                                if (Regex.IsMatch(latin.GetString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                {
                                                    strPipeMsgOut.extra = (int)row["DNSError"];
                                                    strPipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changed_by_internal_filter = true;
                                                    goto skipfilterdns3;
                                                }
                                                break;
                                            case Glob.ActionErrorH:
                                                if (Regex.IsMatch(BytesToHexString(data), row["DNSCatch"].ToString(), RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                                {
                                                    strPipeMsgOut.extra = (int)row["DNSError"];
                                                    strPipeMsgOut.datasize = 0;
                                                    WritePipe();
                                                    rootNode.ForeColor = Color.DarkGray;
                                                    changed_by_internal_filter = true;
                                                    goto skipfilterdns3;
                                                }
                                                break;
                                        }
                                    }
                                }

                                if (!changed_by_internal_filter)
                                {
                                    strPipeMsgOut.datasize = 0;
                                    strPipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                    changed_by_internal_filter = true;
                                }
                                else
                                {
                                    strPipeMsgOut.datasize = data.Length;
                                    strPipeMsgOut.extra = 0;
                                    WritePipe();
                                    pipeOut.Write(data, 0, data.Length);
                                    rootNode.ForeColor = Color.Green;
                                }
                            }
                        skipfilterdns3:
                            break;
                    }
                    break;
            }
            if (filter && !changed_by_internal_filter)
            {
                strPipeMsgOut.command = Glob.CMD_FILTER;
                strPipeMsgOut.datasize = 0;
                strPipeMsgOut.extra = 0; // Error
                WritePipe();
            }
        }

        void ProcessExited()
        {
            pipeIn.Close();
            pipeOut.Close();
            targetPID = 0;
            this.Text = "PacketEditor";
            mnuFileDetach.Enabled = false;
        }

        delegate void UpdateMainGridDelegate(byte[] data);
        delegate void UpdateTreeDelegate(byte[] data);
        delegate void ProcessExitedDelegate();
        delegate void CurrentProcessExited();

        private void PipeRead()
        {
            byte[] pipeMsgInBuffer = new byte[14];
            byte[] zero = new byte[] { 0 };

            Delegate updateMainGrid = new UpdateMainGridDelegate(UpdateMainGrid);
            Delegate exitProc = new ProcessExitedDelegate(ProcessExited);
            Delegate updateTree = new UpdateTreeDelegate(UpdateTree);

            while (pipeIn.Read(pipeMsgInBuffer, 0, 14) != 0 || pipeIn.IsConnected)
            {
                strPipeMsgIn = Glob.RawDeserializeEx<Glob.PipeHeader>(pipeMsgInBuffer);
                if (strPipeMsgIn.datasize != 0)
                {
                    byte[] pipeMsgInDataBuffer = new byte[strPipeMsgIn.datasize];
                    pipeIn.Read(pipeMsgInDataBuffer, 0, pipeMsgInDataBuffer.Length);

                    switch (strPipeMsgIn.function)
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
                                logger.Error(ex, "Invoke UpdateMainGridView failed");
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
                    if (strPipeMsgIn.command == Glob.CMD_INIT)
                    {
                        if (strPipeMsgIn.function == Glob.INIT_DECRYPT)
                        {
                            if (strPipeMsgIn.extra == 0)
                            {
                                Invoke(exitProc);
                                MessageBox.Show(this.Owner, "Invalid license.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                return;
                            }
                            else
                            {
                                strPipeMsgOut.datasize = 0;
                                if (monitor)
                                {
                                    strPipeMsgOut.command = Glob.CMD_ENABLE_MONITOR;
                                    strPipeMsgOut.datasize = 0;
                                    WritePipe();
                                }

                                if (filter)
                                {
                                    strPipeMsgOut.command = Glob.CMD_ENABLE_FILTER;
                                    strPipeMsgOut.datasize = 0;
                                    WritePipe();
                                }
                            }
                        }
                    }
                    else
                    {
                        switch (strPipeMsgIn.function)
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
                                if (filter)
                                {
                                    strPipeMsgOut.command = Glob.CMD_FILTER;
                                    strPipeMsgOut.datasize = 0;
                                    strPipeMsgOut.extra = 0; // Error
                                    WritePipe();
                                }
                                break;
                        }
                    }
                }
            }

            Invoke(exitProc);


            if (MessageBox.Show("Process Exited.\nTry to reattach?", "Alert", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes
                && !TryAttach(processID, processPath)) // TODO: may fail if paramters were not set properly
            {
                var currentProcExited = new CurrentProcessExited(() =>
                {
                    mnuFileDetach.Enabled = false;
                    reAttachToolStripMenuItem.Enabled = true;
                });
                Invoke(currentProcExited);
                //mnuFileDetach.Enabled = false;
                //reAttachToolStripMenuItem.Enabled = true;
            }
        }



        private void mnuFileExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        #region Global Variables for Attach
        string processPath;
        int processID;
        #endregion

        private void mnuFileAttach_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                if (MessageBox.Show("You are curently attached to a process. Are you sure you would like to detach?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Exclamation,
                    MessageBoxDefaultButton.Button2) == DialogResult.No)
                {
                    return;
                }

                if (pipeOut.IsConnected)
                {
                    strPipeMsgOut.command = Glob.CMD_UNLOAD_DLL;
                    try
                    {
                        WritePipe();
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, "Write pipe failed");
                    }
                }

                try
                {
                    if (trdPipeRead.IsAlive)
                    {
                        trdPipeRead.Abort();
                    }
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Read pipe abort failed");
                }

                pipeIn.Close();
                pipeOut.Close();
                targetPID = 0;
                this.Text = appName;
                mnuFileDetach.Enabled = false;
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
                TryAttach(processID, processPath);
            }

            Enabled = true;
        }

        /// <summary>
        /// Check process ID and excute InvokeDLL().
        /// </summary>
        /// <param name="pID">Process ID</param>
        /// <param name="path">Process location</param>
        /// <returns><c>true</c> if attach successfully; otherwise, <c>false</c>.</returns>
        private bool TryAttach(int pID, string path)
        {
            targetPID = pID;
            //this.Enabled = true;
            if (targetPID != 0 && InvokeDLL())
            {
                reAttachPath = path;
                this.Text = appName + " - " + reAttachPath;
                mnuFileDetach.Enabled = true;
                reAttachToolStripMenuItem.Enabled = true;
                return true;
            }
            return false;
        }

        private void frmMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (procExternalFilter != null && !procExternalFilter.HasExited)
            {
                try
                {
                    procExternalFilter.Kill();
                }
                catch (Exception ex)
                {
                    logger.Fatal(ex);
                }
            }

            if (targetPID != 0)
            {
                if (MessageBox.Show("You are curently attached to a process. Are you sure you would like to exit?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                {
                    if (pipeOut.IsConnected)
                    {
                        strPipeMsgOut.command = Glob.CMD_UNLOAD_DLL;
                        try
                        {
                            WritePipe();
                        }
                        catch (Exception ex)
                        {
                            logger.Error(ex, "Write pipe failed while closing main form");
                        }
                    }

                    if (trdPipeRead.IsAlive)
                    {
                        trdPipeRead.Abort();
                    }

                    pipeIn.Close();
                    pipeOut.Close();
                }
                else
                {
                    e.Cancel = true;
                }
            }

            isListeningForRequests = false;
            if (!firstRun)
                httpListener.Close();
        }

        private void mnuFileDetach_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                if (pipeOut.IsConnected)
                {
                    strPipeMsgOut.command = Glob.CMD_UNLOAD_DLL;
                    try
                    {
                        WritePipe();
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, "Write pipe failed while detaching a process");
                    }
                }

                if (trdPipeRead.IsAlive)
                {
                    trdPipeRead.Abort();
                }

                pipeIn.Close();
                pipeOut.Close();
                targetPID = 0;
                this.Text = appName;
                mnuFileDetach.Enabled = false;
                reAttachToolStripMenuItem.Enabled = true;
            }
        }

        private void mnuToolsMonitor_CheckedChanged(object sender, EventArgs e)
        {
            if (mnuToolsMonitor.Checked)
            {
                monitor = true;
                DNStrap = false;
                if (targetPID != 0)
                {
                    strPipeMsgOut.command = Glob.CMD_ENABLE_MONITOR;
                    strPipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
            else
            {
                monitor = false;
                DNStrap = false;
                if (targetPID != 0)
                {
                    strPipeMsgOut.command = Glob.CMD_DISABLE_MONITOR;
                    strPipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
        }

        private void frmMain_Resize(object sender, EventArgs e)
        {
            //if (FormWindowState.Minimized == WindowState)
            //{
            //icoNotify.Visible = true;
            //Hide();
            //}
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
                logger.Fatal("{0} not found", dllFullPath);
                this.Close();
            }

            tsExternalFilter.BackColor = Color.Red;
        }

        private void mnuMsgSocketSDrecv_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Receive;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketSDsend_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Send;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketSDboth_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_SHUTDOWN;
                strPipeMsgOut.extra = (int)SocketShutdown.Both;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuMsgSocketClose_Click(object sender, EventArgs e)
        {
            if (dgridMain.SelectedRows.Count != 0)
            {
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.function = Glob.FUNC_CLOSESOCKET;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuToolsFilter_CheckedChanged(object sender, EventArgs e)
        {
            if (mnuToolsFilter.Checked)
            {
                filter = true;
                if (targetPID != 0)
                {
                    strPipeMsgOut.command = Glob.CMD_ENABLE_FILTER;
                    strPipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
            else
            {
                filter = false;
                if (targetPID != 0)
                {
                    strPipeMsgOut.command = Glob.CMD_DISABLE_FILTER;
                    strPipeMsgOut.datasize = 0;
                    WritePipe();
                }
            }
        }

        private void mnuOptionsOntop_CheckedChanged(object sender, EventArgs e)
        {
            if (mnuOptionsOntop.Checked)
            {
                this.TopMost = true;
            }
            else
            {
                this.TopMost = false;
            }
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
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.function = Glob.FUNC_SEND;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.datasize = ((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value).Length;
                WritePipe();
                try
                {
                    pipeOut.Write((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value, 0, strPipeMsgOut.datasize);
                }
                catch (Exception ex)
                {
                    logger.Error(ex);
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
                strPipeMsgOut.command = Glob.CMD_FREEZE;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
            else
            {
                mnuInvokeFreeze.Text = freezeState;
                strPipeMsgOut.command = Glob.CMD_UNFREEZE;
                strPipeMsgOut.datasize = 0;
                WritePipe();
            }
        }

        private void mnuFileOpen_Click(object sender, EventArgs e)
        {
            if (targetPID != 0)
            {
                if (MessageBox.Show("You are curently attached to a process. Are you sure you would like to detach?",
                                    "Confirm",
                                    MessageBoxButtons.YesNo,
                                    MessageBoxIcon.Warning,
                                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    return;
                }

                if (pipeOut.IsConnected)
                {
                    strPipeMsgOut.command = Glob.CMD_UNLOAD_DLL;
                    try
                    {
                        WritePipe();
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex);
                    }
                }

                if (trdPipeRead.IsAlive)
                {
                    trdPipeRead.Abort();
                }

                pipeIn.Close();
                pipeOut.Close();
                targetPID = 0;
                this.Text = appName;
                mnuFileDetach.Enabled = false;
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

                var proc = new Process();
                proc.StartInfo.FileName = ofd.FileName;
                proc.StartInfo.WorkingDirectory = ofd.FileName.Substring(0, ofd.FileName.LastIndexOf('\\') + 1);
                proc.Start();

                targetPID = proc.Id;
                processID = proc.Id;
                processPath = ofd.FileName;
                if (InvokeDLL())
                {
                    this.Text = appName + " - " + ofd.FileName;
                    mnuFileDetach.Enabled = true;
                }
            }
        }

        private void mnuHelpHelp_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Currently not available");
            //Process.Start("https://appsec-labs.com/Advanced_Packet_Editor");
        }

        private void mnuHelpWebsite_Click(object sender, EventArgs e)
        {
            var frmChAbout = new frmAbout();
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
            string data = "";
            for (int i = 0; i < dgridMain.SelectedRows.Count; i++)
                data += dgridMain.SelectedRows[i].Cells["data"].Value;

            if (data != string.Empty)
                Clipboard.SetData(DataFormats.Text, data.Replace("\0", "\\0"));
        }

        private void mnuMsgCopyHex_Click(object sender, EventArgs e)
        {
            string data = "";
            try
            {
                for (int i = 0; i < dgridMain.SelectedRows.Count; i++)
                    data += BytesToHexString((byte[])dgridMain.SelectedRows[i].Cells["rawdata"].Value);

                if (data != string.Empty)
                    Clipboard.SetData(DataFormats.Text, data);
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Copy hex data failed");
            }
        }

        private void filtersToolStripMenuItem_Click(object sender, EventArgs e)
        {
            frmChFilters.BringToFront();
        }

        private void reAttachToolStripMenuItem_Click(object sender, EventArgs e)
        {
            reattacheDelayInMs = Interaction.InputBox("Delay in milliseconds (1000 = 1 second)", "Reattach delay", reattacheDelayInMs);
            if (reattacheDelayInMs == string.Empty || !int.TryParse(reattacheDelayInMs, out int ms))
                return;

            Thread.Sleep(ms);

            if (targetPID != 0)
            {
                if (MessageBox.Show("You are curently attached to a process. Are you sure you would like to detach?",
                    "Confirm",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                {
                    return;
                }

                if (pipeOut.IsConnected)
                {
                    strPipeMsgOut.command = Glob.CMD_UNLOAD_DLL;
                    try
                    {
                        WritePipe();
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, "Reattach WritePipe failed");
                    }
                }

                if (trdPipeRead.IsAlive)
                {
                    trdPipeRead.Abort();
                }

                pipeIn.Close();
                pipeOut.Close();
                targetPID = 0;
                this.Text = appName;
                mnuFileDetach.Enabled = false;
            }

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.MainModule.FileName == reAttachPath)
                    {
                        targetPID = process.Id;
                        break;
                    }
                }
                catch (System.ComponentModel.Win32Exception w)
                {
                    logger.Warn(w, "32 or 64 bit issue");
                }
                catch (Exception ex)
                {
                    logger.Error(ex);
                }
            }

            if (targetPID != 0 && InvokeDLL())
            {
                this.Text = appName + " - " + reAttachPath;
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
                isListeningForRequests = true;

                try
                {
                    string listenerPort = Interaction.InputBox("On which port you want to listen?", "Start listen for requests", "8083");
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

                        isListeningForRequests = true;

                        new Thread(new ThreadStart(Listening)).Start();
                    }
                    isListeningForRequests = true;

                    new FrmBurpCode(burpRequest).ShowDialog();
                }
                catch (HttpListenerException hle)
                {
                    logger.Error(hle, "HttpListenerException Error code: {0}", hle.ErrorCode);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error occurred. Did you run it with administrator privileges?");
                    //MnuToolsProxy.Checked = false;
                    logger.Error(ex);
                }
            }
            else
            {
                // stop the listen
                isListeningForRequests = false;
                //listener.Close();
            }
        }

        private void Listening()
        {
            var callback = new AsyncCallback(ListenerCallback);
            while (isListeningForRequests)
            {
                IAsyncResult result = httpListener.BeginGetContext(callback, httpListener);
                result.AsyncWaitHandle.WaitOne();
            }

            httpListener.Close();
        }

        protected void ListenerCallback(IAsyncResult result)
        {
            if (httpListener == null)
                return;

            try
            {
                HttpListenerContext context = httpListener.EndGetContext(result);

                httpListener.BeginGetContext(new AsyncCallback(ListenerCallback), httpListener);

                ReceiveWebRequest?.Invoke(context);

                ProcessRequest(context);
            }
            catch (HttpListenerException ex)
            {
                //  The I/O operation has been aborted because of either a thread exit or an application request.
                const int ErrorOperationAborted = 995;
                if (ex.ErrorCode != ErrorOperationAborted)
                {
                    logger.Error(ex);
                    throw;
                }

                MessageBox.Show($"Swallowing HttpListenerException({ErrorOperationAborted}) Thread exit or aborted request");
            }
        }

        /// <summary>
        /// Overridable method that can be used to implement a custom handler
        /// </summary>
        /// <param name="context"></param>

        protected void ProcessRequest(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;


            StringBuilder sb = new StringBuilder();
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
                errorMsg = "Error: sockid is wrong or missing";
            }

            if (int.TryParse(socketNum, NumberStyles.HexNumber, CultureInfo.CurrentCulture, out int socketId))
            {
                strPipeMsgOut.sockid = socketId;
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

                    strPipeMsgOut.command = Glob.CMD_INJECT;
                    strPipeMsgOut.function = SocketInfoUtils.MsgNum(method); // Glob.FUNC_SEND;
                    strPipeMsgOut.datasize = bcBytes.Length;
                    WritePipe();
                    try
                    {
                        pipeOut.Write(bcBytes, 0, strPipeMsgOut.datasize);
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex);
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
                    if (showToolStripMenuItem.Checked)
                        row.Visible = true;
                    else
                        row.Visible = false;
                }
            }
        }

        private void showrecvRecvAllToolStripMenuItem_CheckedChanged(object sender, EventArgs e)
        {
            foreach (DataGridViewRow row in dgridMain.Rows)
            {
                if (row.Cells["method"].Value.ToString().Contains("ecv"))
                {
                    if (showrecvRecvAllToolStripMenuItem.Checked)
                        row.Visible = true;
                    else
                        row.Visible = false;
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
                txbRecordText.Text = dgridMain.SelectedRows[0].Cells["data"].Value.ToString();
            }
        }

        private Process procExternalFilter;
        private FrmPython Python;

        private void ActivateExtenalFilter()
        {
            string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            if (!File.Exists(appDirectory + @"\scripts\external_filter_server.py"))
            {
                logger.Fatal("{0} does not exist", appDirectory + @"\scripts\external_filter_server.py");
                return;
            }

            int port = GetExternalFilterPort();
            if (port == -1)
            {
                externalFilter = false;
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

            tsExternalFilter.BackColor = Color.Green;

            if (Python == null)
            {
                try
                {
                    procExternalFilter.Start();
                    timerPython.Start();
                    Python = new FrmPython(logFileName);
                    Python.Show();
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
                if (Python != null)
                {
                    Python.Close();
                    Python = null;
                }

                if (procExternalFilter != null && !procExternalFilter.HasExited)
                {
                    procExternalFilter.Kill();
                }

                tsExternalFilter.BackColor = Color.Red;
            }
            catch (Exception ex)
            {
                logger.Error(ex);
            }
        }

        private void toolToggleFilter_Click(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
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
                strPipeMsgOut.command = Glob.CMD_INJECT;
                strPipeMsgOut.function = Glob.FUNC_SEND;
                strPipeMsgOut.sockid = int.Parse(dgridMain.SelectedRows[0].Cells["socket"].Value.ToString(), NumberStyles.AllowHexSpecifier);
                strPipeMsgOut.datasize = ((byte[])dgridMain.SelectedRows[0].Cells["rawdata"].Value).Length;
                WritePipe();
                try
                {
                    pipeOut.Write(Encoding.ASCII.GetBytes(txbRecordText.Text), 0, strPipeMsgOut.datasize);
                }
                catch (Exception ex)
                {
                    logger.Error(ex);
                }
            }
        }

        private void timerPython_Tick(object sender, EventArgs e)
        {
            try
            {
                if (procExternalFilter.HasExited)
                    tsExternalFilter.BackColor = Color.Red;
                else
                    tsExternalFilter.BackColor = Color.Green;
            }
            catch (Exception ex)
            {
                tsExternalFilter.BackColor = Color.Red;
                timerPython.Stop();

                logger.Error(ex);
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
    }
}
