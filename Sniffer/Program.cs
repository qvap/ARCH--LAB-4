using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SnifferTesting
{
    class Program
    {
        static void Main(string[] args)
        {   
            string? ipaddress = "255.255.255.255";
            bool flag = true;
            Console.Write("Введите локальный ip-адрес: ");
            while(flag)
            {
                ipaddress = Console.ReadLine();
                Regex regex = new Regex(@"^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$");
                if (!string.IsNullOrWhiteSpace(ipaddress) && regex.IsMatch(ipaddress))
                {
                    flag = false;
                }
            }
            try
            {
                if (!string.IsNullOrWhiteSpace(ipaddress))
                {
                    Sniffer sniffer = new Sniffer();
                    sniffer.startSocket(ipaddress);
                    Console.WriteLine("Сниффер запущен. Нажмите Enter для выхода...");
                    Console.ReadLine();
                }

            }
            catch(Exception ex)
            {
                Console.WriteLine("[ОШИБКА] " + ex.Message); 
            }
        }
    }

    public class Sniffer
    {
        private Socket mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        private byte[] byteData = new byte[4096];

        public void startSocket(string ipAdress){
            mainSocket.Bind(new IPEndPoint(IPAddress.Parse(ipAdress), 0));
            mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            byte[] byTrue = new byte[4]{1, 0, 0, 0};
            byte[] byOut = new byte[4];

            mainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
            mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);
                IPHeader ipheader = new IPHeader(byteData, nReceived);

                Console.WriteLine("\n" + new string('=', 80));
                Console.WriteLine("НОВЫЙ IP ПАКЕТ ПОЛУЧЕН");
                Console.WriteLine(new string('=', 80));
                
                // Основная информация IP
                Console.WriteLine($"IP Версия: {ipheader.Version}");
                Console.WriteLine($"Длина заголовка IP: {ipheader.HeaderLength} байт");
                Console.WriteLine($"Тип службы: 0x{ipheader.TypeOfService:X2}");
                Console.WriteLine($"Общая длина пакета: {ipheader.TotalLength} байт");
                Console.WriteLine($"Идентификатор: {ipheader.Identification}");
                Console.WriteLine($"Флаги: 0x{ipheader.Flags:X} {ipheader.FlagsDescription}");
                Console.WriteLine($"Смещение фрагмента: {ipheader.FragmentOffset}");
                Console.WriteLine($"Время жизни (TTL): {ipheader.TTL}");
                Console.WriteLine($"Протокол: {ipheader.Protocol} ({ipheader.ProtocolNumber})");
                Console.WriteLine($"Контрольная сумма заголовка: 0x{ipheader.Checksum:X4}");
                Console.WriteLine($"IP-адрес источника: {ipheader.SourceAddress}");
                Console.WriteLine($"IP-адрес назначения: {ipheader.DestinationAddress}");
                Console.WriteLine($"Размер данных после IP заголовка: {ipheader.DataLength} байт");

                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ОШИБКА] " + ex.Message);  
            }
        }
    }    public class IPHeader
    {
        private byte byVersionAndHeaderLength;// Восемь бит для версии и длины
        private byte byDifferentiatedServices;
        private ushort usTotalLength;
        private ushort usIdentification;
        private ushort usFlagsAndOffset;
        private byte byTTL;
        private byte byProtocol;
        private short sChecksum;
        private uint uiSourcelIPAdress;
        private uint uiDestinationIPAdress;
        
        private byte byHeaderLength;
        private byte byVersion;
        private ushort usMessageLength;
        byte[] byIPData = new byte[4096];
        
        public IPHeader(byte[] byBuffer, int nReceived)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                byVersionAndHeaderLength = binaryReader.ReadByte();
                byDifferentiatedServices = binaryReader.ReadByte();
                usTotalLength = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usIdentification = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usFlagsAndOffset = (ushort) IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                byTTL = binaryReader.ReadByte();
                byProtocol = binaryReader.ReadByte();
                sChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                uiSourcelIPAdress = (uint)(binaryReader.ReadInt32());
                uiDestinationIPAdress = (uint)(binaryReader.ReadInt32());
                
                // Извлекаем версию и длину заголовка
                byVersion = (byte)(byVersionAndHeaderLength >> 4);
                byHeaderLength = (byte)((byVersionAndHeaderLength & 0x0F) * 4);

                // Вычисляем длину данных
                usMessageLength = (ushort)(usTotalLength - byHeaderLength);
                if (usMessageLength > 0 && usMessageLength <= nReceived - byHeaderLength)
                {
                    Array.Copy(byBuffer, byHeaderLength, byIPData, 0, usMessageLength);
                }
                else
                {
                    usMessageLength = 0;
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("[ОШИБКА] " + ex.Message); 
            }
        }

        // Основные свойства
        public IPAddress SourceAddress => new IPAddress(uiSourcelIPAdress);
        public IPAddress DestinationAddress => new IPAddress(uiDestinationIPAdress);
        public byte Version => byVersion;
        public byte HeaderLength => byHeaderLength;
        public byte TypeOfService => byDifferentiatedServices;
        public ushort TotalLength => usTotalLength;
        public ushort Identification => usIdentification;
        public ushort Flags => (ushort)((usFlagsAndOffset >> 13) & 0x07);
        public ushort FragmentOffset => (ushort)(usFlagsAndOffset & 0x1FFF);
        public byte TTL => byTTL;
        public byte ProtocolNumber => byProtocol;
        public short Checksum => sChecksum;
        public ushort DataLength => usMessageLength;
        public byte[] Data => byIPData;
        
        // Вспомогательные свойства
        public string Protocol
        {
            get
            {
                return byProtocol switch
                {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    41 => "IPv6",
                    47 => "GRE",
                    50 => "ESP",
                    51 => "AH",
                    _ => $"Unknown ({byProtocol})"
                };
            }
        }

        public string FlagsDescription
        {
            get
            {
                var flags = new List<string>();
                ushort flagValue = Flags;
                if ((flagValue & 0x04) != 0) flags.Add("DF"); // Don't Fragment
                if ((flagValue & 0x02) != 0) flags.Add("MF"); // More Fragments
                if ((flagValue & 0x01) != 0) flags.Add("Reserved");
                return flags.Count > 0 ? $"({string.Join(", ", flags)})" : "";
            }
        }

        public bool HasOptions => byHeaderLength > 20;
        public byte OptionsLength => (byte)(byHeaderLength > 20 ? byHeaderLength - 20 : 0);
    }
}

