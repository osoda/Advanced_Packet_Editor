using System;
using System.Net.Sockets;

namespace PacketEditor
{
    // TODO: Replace by C# built in enums. And make this class static
    static class SocketInfoUtils
    {
        // Sockets.AddressFamily 19
        static readonly string[] afamily = new string[] { "UNSPEC", "UNIX", "INET", "IMPLINK", "PUP", "CHAOS", "NS", "ISO", "ECMA", "DATAKIT", "CCITT", "SNA", "DECnet", "DLI", "LAT", "HYLINK", "APPLETALK", "NETBIOS", "MAX" };
        // Sockets.SocketType 6
        static readonly string[] atype = new string[] { "", "STREAM", "DGRAM", "RAW", "RDM", "SEQPACKET" };
        // Sockets.SocketShutdown
        static readonly string[] sdhow = new string[] { "RECEIVE", "SEND", "BOTH" };
        public const string sockIdFmt = "X4";

        public static string AddressFamilyName(int af)
        {
            string addressFamily = Enum.GetName(typeof(AddressFamily), af);

            return addressFamily?.ToUpper() ?? string.Empty;
        }

        public static string SocketTypeName(int st)
        {
            string socketType = Enum.GetName(typeof(SocketType), st);

            return socketType?.ToUpper() ?? string.Empty;
        }

        public static string SocketShutdownName(int sd)
        {
            string socketShutdown = Enum.GetName(typeof(SocketShutdown), sd);

            return socketShutdown?.ToUpper() ?? string.Empty;
        }

        public static string ProtocolName(int proto)
        {
            string protocolType = Enum.GetName(typeof(ProtocolType), proto);
            if (protocolType != null)
            {
                return protocolType.ToUpper();
            }

            if (proto == 256)
                return "MAX";
            return "UNKNOWN";
        }

        public static string Msg(int function)
        {
            switch (function)
            {
                case Glob.FUNC_SEND:
                    return "send()";
                case Glob.FUNC_SENDTO:
                    return "sendto()";
                case Glob.FUNC_WSASEND:
                    return "WSASend()";
                case Glob.FUNC_WSASENDTO:
                    return "WSASendTo()";
                case Glob.FUNC_WSASENDDISCONNECT:
                    return "WSASendDisconnect()";
                case Glob.FUNC_RECV:
                    return "recv()";
                case Glob.FUNC_RECVFROM:
                    return "recvfrom()";
                case Glob.FUNC_WSARECV:
                    return "WSARecv()";
                case Glob.FUNC_WSARECVFROM:
                    return "WSARecvFrom()";
                case Glob.FUNC_WSARECVDISCONNECT:
                    return "WSARecvDisconnect()";
                default:
                    return "";
            }
        }

        public static string Api(int function)
        {
            switch (function)
            {
                case Glob.FUNC_WSAACCEPT:
                    return "WSAAccept()";
                case Glob.FUNC_ACCEPT:
                    return "accept()";
                case Glob.FUNC_WSACONNECT:
                    return "WSAConnect()";
                case Glob.FUNC_CONNECT:
                    return "connect()";
                case Glob.FUNC_WSASOCKETW_IN:
                case Glob.FUNC_WSASOCKETW_OUT:
                    return "WSASocket()";
                case Glob.FUNC_BIND:
                    return "bind()";
                case Glob.CONN_WSASENDTO:
                    return "WSASendTo()";
                case Glob.CONN_WSARECVFROM:
                    return "WSARecvFrom()";
                case Glob.CONN_SENDTO:
                    return "sendto()";
                case Glob.CONN_RECVFROM:
                    return "recvfrom()";
                case Glob.FUNC_SOCKET_IN:
                case Glob.FUNC_SOCKET_OUT:
                    return "socket()";
                case Glob.FUNC_CLOSESOCKET:
                    return "closesocket()";
                case Glob.FUNC_LISTEN:
                    return "listen()";
                case Glob.FUNC_SHUTDOWN:
                    return "shutdown()";
                case Glob.FUNC_WSASENDDISCONNECT:
                    return "WSASendDisconnect()";
                case Glob.FUNC_WSARECVDISCONNECT:
                    return "WSARecvDisconnect()";
                case Glob.DNS_GETHOSTNAME:
                    return "gethostname()";
                case Glob.DNS_GETHOSTBYADDR_IN:
                case Glob.DNS_GETHOSTBYADDR_OUT:
                    return "gethostbyaddr()";
                case Glob.DNS_GETHOSTBYNAME_IN:
                case Glob.DNS_GETHOSTBYNAME_OUT:
                    return "gethostbyname()";
                default:
                    return "";
            }
        }

        public static byte MsgNum(string name)
        {
            switch (name)
            {
                case "send()":
                    return Glob.FUNC_SEND;
                case "sendto()":
                    return Glob.FUNC_SENDTO;
                case "WSASend()":
                    return Glob.FUNC_WSASEND;
                case "WSASendTo()":
                    return Glob.FUNC_WSASENDTO;
                case "WSASendDisconnect()":
                    return Glob.FUNC_WSASENDDISCONNECT;
                case "recv()":
                    return Glob.FUNC_RECV;
                case "recvfrom()":
                    return Glob.FUNC_RECVFROM;
                case "WSARecv()":
                    return Glob.FUNC_WSARECV;
                case "WSARecvFrom()":
                    return Glob.FUNC_WSARECVFROM;
                case "WSARecvDisconnect()":
                    return Glob.FUNC_WSARECVDISCONNECT;
                default:
                    return 0;
            }
        }

        public static byte ApiNum(string name)
        {
            switch (name)
            {
                case "WSAAccept()":
                    return Glob.FUNC_WSAACCEPT;
                case "accept()":
                    return Glob.FUNC_ACCEPT;
                case "WSAConnect()":
                    return Glob.FUNC_WSACONNECT;
                case "connect()":
                    return Glob.FUNC_CONNECT;
                case "WSASocket()":
                    return Glob.FUNC_WSASOCKETW_IN;
                case "bind()":
                    return Glob.FUNC_BIND;
                case "WSASendTo()":
                    return Glob.CONN_WSASENDTO;
                case "WSARecvFrom()":
                    return Glob.CONN_WSARECVFROM;
                case "sendto()":
                    return Glob.CONN_SENDTO;
                case "recvfrom()":
                    return Glob.CONN_RECVFROM;
                case "socket()":
                    return Glob.FUNC_SOCKET_IN;
                case "closesocket()":
                    return Glob.FUNC_CLOSESOCKET;
                case "listen()":
                    return Glob.FUNC_LISTEN;
                case "shutdown()":
                    return Glob.FUNC_SHUTDOWN;
                case "gethostname()":
                    return Glob.DNS_GETHOSTNAME;
                case "gethostbyname()":
                    return Glob.DNS_GETHOSTBYNAME_OUT;
                case "gethostbyaddr()":
                    return Glob.DNS_GETHOSTBYADDR_OUT;
                default:
                    return 0;
            }
        }

        public static int ErrorNum(string name)
        {
            switch (name)
            {
                case "WSA_IO_PENDING":
                    return 10035;
                case "WSA_OPERATION_ABORTED":
                    return 10004;
                case "WSAEACCES":
                    return 10013;
                case "WSAEADDRINUSE":
                    return 10048;
                case "WSAEADDRNOTAVAIL":
                    return 10049;
                case "WSAEAFNOSUPPORT":
                    return 10047;
                case "WSAEALREADY":
                    return 10037;
                case "WSAECONNABORTED":
                    return 10053;
                case "WSAECONNREFUSED":
                    return 10061;
                case "WSAECONNRESET":
                    return 10054;
                case "WSAEDESTADDRREQ":
                    return 10039;
                case "WSAEDISCON":
                    return 10101;
                case "WSAEFAULT":
                    return 10014;
                case "WSAEHOSTUNREACH":
                    return 10065;
                case "WSAEINPROGRESS":
                    return 10036;
                case "WSAEINTR":
                    return 10004;
                case "WSAEINVAL":
                    return 10022;
                case "WSAEISCONN":
                    return 10056;
                case "WSAEMFILE":
                    return 10024;
                case "WSAEMSGSIZE":
                    return 10040;
                case "WSAENETDOWN":
                    return 10050;
                case "WSAENETRESET":
                    return 10052;
                case "WSAENETUNREACH":
                    return 10051;
                case "WSAENOBUFS":
                    return 10055;
                case "WSAENOPROTOOPT":
                    return 10042;
                case "WSAENOTCONN":
                    return 10057;
                case "WSAENOTSOCK":
                    return 10038;
                case "WSAEOPNOTSUPP":
                    return 10045;
                case "WSAEPROTONOSUPPORT":
                    return 10043;
                case "WSAEPROTOTYPE":
                    return 10041;
                case "WSAESHUTDOWN":
                    return 10058;
                case "WSAESOCKTNOSUPPORT":
                    return 10044;
                case "WSAETIMEDOUT":
                    return 10060;
                case "WSAEWOULDBLOCK":
                    return 10035;
                case "WSAHOST_NOT_FOUND":
                    return 11001;
                case "WSANO_DATA":
                    return 11004;
                case "WSANO_RECOVERY":
                    return 11003;
                case "WSANOTINITIALISED":
                    return 10093;
                case "WSATRY_AGAIN":
                    return 11002;
                case "NO_ERROR":
                default:
                    return 0;
            }
        }

        public static string Error(int error)
        {
            switch (error)
            {
                case 10013:
                    return "WSAEACCES";
                case 10048:
                    return "WSAEADDRINUSE";
                case 10049:
                    return "WSAEADDRNOTAVAIL";
                case 10047:
                    return "WSAEAFNOSUPPORT";
                case 10037:
                    return "WSAEALREADY";
                case 10053:
                    return "WSAECONNABORTED";
                case 10061:
                    return "WSAECONNREFUSED";
                case 10054:
                    return "WSAECONNRESET";
                case 10039:
                    return "WSAEDESTADDRREQ";
                case 10101:
                    return "WSAEDISCON";
                case 10014:
                    return "WSAEFAULT";
                case 10065:
                    return "WSAEHOSTUNREACH";
                case 10036:
                    return "WSAEINPROGRESS";
                case 10004:
                    return "WSAEINTR";
                case 10022:
                    return "WSAEINVAL";
                case 10056:
                    return "WSAEISCONN";
                case 10024:
                    return "WSAEMFILE";
                case 10040:
                    return "WSAEMSGSIZE";
                case 10050:
                    return "WSAENETDOWN";
                case 10052:
                    return "WSAENETRESET";
                case 10051:
                    return "WSAENETUNREACH";
                case 10055:
                    return "WSAENOBUFS";
                case 10042:
                    return "WSAENOPROTOOPT";
                case 10057:
                    return "WSAENOTCONN";
                case 10038:
                    return "WSAENOTSOCK";
                case 10045:
                    return "WSAEOPNOTSUPP";
                case 10043:
                    return "WSAEPROTONOSUPPORT";
                case 10041:
                    return "WSAEPROTOTYPE";
                case 10058:
                    return "WSAESHUTDOWN";
                case 10044:
                    return "WSAESOCKTNOSUPPORT";
                case 10060:
                    return "WSAETIMEDOUT";
                case 10035:
                    return "WSAEWOULDBLOCK";
                case 11001:
                    return "WSAHOST_NOT_FOUND";
                case 11004:
                    return "WSANO_DATA";
                case 11003:
                    return "WSANO_RECOVERY";
                case 10093:
                    return "WSANOTINITIALISED";
                case 11002:
                    return "WSATRY_AGAIN";
                case 0:
                default:
                    return "NO_ERROR";
            }
        }
    }
}
