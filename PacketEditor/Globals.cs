using System;
using System.Runtime.InteropServices;

namespace PacketEditor
{
    public class Glob
    {
        public const byte INIT_DECRYPT = 1;

        public const byte FUNC_NULL = 0;
        public const byte FUNC_WSASEND = 1;
        public const byte FUNC_WSARECV = 2;
        public const byte FUNC_SEND = 3;
        public const byte FUNC_RECV = 4;
        public const byte FUNC_WSASENDTO = 5;
        public const byte FUNC_WSARECVFROM = 6;
        public const byte FUNC_SENDTO = 7;
        public const byte FUNC_RECVFROM = 8;
        public const byte FUNC_WSASENDDISCONNECT = 9;
        public const byte FUNC_WSARECVDISCONNECT = 10;
        public const byte FUNC_WSAACCEPT = 11;
        public const byte FUNC_ACCEPT = 12;
        public const byte FUNC_WSACONNECT = 13;
        public const byte FUNC_CONNECT = 14;
        public const byte FUNC_WSASOCKETW_IN = 15;
        public const byte FUNC_WSASOCKETW_OUT = 16;
        public const byte FUNC_BIND = 17;
        public const byte FUNC_CLOSESOCKET = 18;
        public const byte FUNC_LISTEN = 19;
        public const byte FUNC_SHUTDOWN = 20;
        public const byte CONN_WSASENDTO = 21;
        public const byte CONN_WSARECVFROM = 22;
        public const byte CONN_SENDTO = 23;
        public const byte CONN_RECVFROM = 24;
        public const byte DNS_GETHOSTBYNAME_OUT = 25;
        public const byte DNS_GETHOSTBYNAME_IN = 26;
        public const byte DNS_GETHOSTBYADDR_OUT = 27;
        public const byte DNS_GETHOSTBYADDR_IN = 28;
        public const byte DNS_WSAASYNCGETHOSTBYNAME_OUT = 29;
        public const byte DNS_WSAASYNCGETHOSTBYNAME_IN = 30;
        public const byte DNS_WSAASYNCGETHOSTBYADDR_OUT = 31;
        public const byte DNS_WSAASYNCGETHOSTBYADDR_IN = 32;
        public const byte DNS_GETHOSTNAME = 33;
        public const byte FUNC_WSACLEANUP = 34;
        public const byte FUNC_SOCKET_IN = 35;
        public const byte FUNC_SOCKET_OUT = 36;
        public const byte FUNC_GETSOCKNAME = 37;
        public const byte FUNC_GETPEERNAME = 38;

        public enum CMD : byte
        {
            Data = 1,
            StructData = 2,
            NoFilterData = 3,
            NoFilterStructData = 4,
            NoData = 5,
            DnsData = 6,
            DnsStructData = 7,
            Init = 8,
            Deinit = 9,

            Query = 245,
            Unfreeze = 246,
            Freeze = 247,
            Filter = 248,
            Recv = 249,
            Inject = 250,
            DisableFilter = 251,
            EnableFilter = 252,
            DisableMonitor = 253,
            EnableMonitor = 254,
            UnloadDll = 255
        }

        public enum Action : byte
        {
            ReplaceString = 0,
            ReplaceStringHex,
            Error,
            ErrorHex
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct PipeHeader
        {
            [MarshalAs(UnmanagedType.I1)]
            public CMD command;
            public byte function;
            [MarshalAs(UnmanagedType.I4)]
            public int sockid;
            public int datasize;
            public int extra;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        public struct Sockaddr_in
        {
            [MarshalAs(UnmanagedType.I2)]
            public short sin_family;
            public ushort sin_port;
            [MarshalAs(UnmanagedType.I1)]
            public byte s_b1;
            public byte s_b2;
            public byte s_b3;
            public byte s_b4;
            [MarshalAs(UnmanagedType.I8)]
            public long sin_zero;
        }

        public static byte[] RawSerializeEx(object anything)
        {
            int rawSize = Marshal.SizeOf(anything);
            byte[] rawdatas = new byte[rawSize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(anything, buffer, false);
            handle.Free();
            return rawdatas;
        }

        public static T RawDeserializeEx<T>(byte[] rawData)
        {
            int rawSize = Marshal.SizeOf(typeof(T));
            if (rawSize > rawData.Length)
                return default;

            GCHandle handle = GCHandle.Alloc(rawData, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            object retObj = Marshal.PtrToStructure(buffer, typeof(T));
            handle.Free();
            return (T)retObj;
        }
    }
}