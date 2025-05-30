using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
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

                // Парсинг пакетов по протоколам
                if (ipheader.DataLength > 0)
                {
                    switch (ipheader.ProtocolNumber)
                    {
                        case 6: // TCP
                            try
                            {
                                TCPHeader tcpHeader = new TCPHeader(ipheader.Data, ipheader.DataLength);
                                Console.WriteLine(new string('-', 60));
                                Console.WriteLine("TCP ЗАГОЛОВОК:");
                                Console.WriteLine($"Порт источника: {tcpHeader.SourcePort}");
                                Console.WriteLine($"Порт назначения: {tcpHeader.DestinationPort}");
                                Console.WriteLine($"Номер последовательности: {tcpHeader.SequenceNumber}");
                                Console.WriteLine($"Номер подтверждения: {tcpHeader.AcknowledgmentNumber}");
                                Console.WriteLine($"Длина заголовка TCP: {tcpHeader.HeaderLength} байт");
                                Console.WriteLine($"Флаги: {tcpHeader.FlagsDescription}");
                                Console.WriteLine($"Размер окна: {tcpHeader.WindowSize}");
                                Console.WriteLine($"Контрольная сумма: 0x{tcpHeader.Checksum:X4}");
                                Console.WriteLine($"Указатель срочности: {tcpHeader.UrgentPointer}");
                                if (tcpHeader.DataLength > 0)
                                {
                                    Console.WriteLine($"TCP данные: {tcpHeader.DataLength} байт");
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[ОШИБКА TCP] {ex.Message}");
                            }
                            break;

                        case 17: // UDP
                            try
                            {
                                UDPHeader udpHeader = new UDPHeader(ipheader.Data, ipheader.DataLength);
                                Console.WriteLine(new string('-', 60));
                                Console.WriteLine("UDP ЗАГОЛОВОК:");
                                Console.WriteLine($"Порт источника: {udpHeader.SourcePort}");
                                Console.WriteLine($"Порт назначения: {udpHeader.DestinationPort}");
                                Console.WriteLine($"Длина UDP: {udpHeader.Length} байт");
                                Console.WriteLine($"Контрольная сумма: 0x{udpHeader.Checksum:X4}");
                                if (udpHeader.DataLength > 0)
                                {
                                    Console.WriteLine($"UDP данные: {udpHeader.DataLength} байт");
                                    
                                    // Проверяем, является ли это DNS запросом/ответом (порт 53)
                                    if (udpHeader.SourcePort == 53 || udpHeader.DestinationPort == 53)
                                    {
                                        try
                                        {
                                            DNSHeader dnsHeader = new DNSHeader(udpHeader.Data, udpHeader.DataLength);
                                            Console.WriteLine(new string('-', 40));
                                            Console.WriteLine("DNS ЗАГОЛОВОК:");
                                            Console.WriteLine($"ID транзакции: 0x{dnsHeader.TransactionID:X4}");
                                            Console.WriteLine($"Тип: {(dnsHeader.IsResponse ? "Ответ" : "Запрос")}");
                                            Console.WriteLine($"Опкод: {dnsHeader.Opcode}");
                                            Console.WriteLine($"Авторитативный ответ: {dnsHeader.AuthoritativeAnswer}");
                                            Console.WriteLine($"Обрезанный: {dnsHeader.Truncated}");
                                            Console.WriteLine($"Рекурсия желательна: {dnsHeader.RecursionDesired}");
                                            Console.WriteLine($"Рекурсия доступна: {dnsHeader.RecursionAvailable}");
                                            Console.WriteLine($"Код ответа: {dnsHeader.ResponseCode}");
                                            Console.WriteLine($"Количество вопросов: {dnsHeader.QuestionCount}");
                                            Console.WriteLine($"Количество ответов: {dnsHeader.AnswerCount}");
                                            Console.WriteLine($"Количество серверов имен: {dnsHeader.AuthorityCount}");
                                            Console.WriteLine($"Количество дополнительных записей: {dnsHeader.AdditionalCount}");
                                            
                                            if (dnsHeader.Questions.Count > 0)
                                            {
                                                Console.WriteLine("DNS Вопросы:");
                                                foreach (var question in dnsHeader.Questions)
                                                {
                                                    Console.WriteLine($"  - {question}");
                                                }
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[ОШИБКА DNS] {ex.Message}");
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[ОШИБКА UDP] {ex.Message}");
                            }
                            break;

                        case 1: // ICMP
                            Console.WriteLine(new string('-', 60));
                            Console.WriteLine("ICMP ПАКЕТ (парсинг не реализован)");
                            break;

                        default:
                            Console.WriteLine(new string('-', 60));
                            Console.WriteLine($"НЕИЗВЕСТНЫЙ ПРОТОКОЛ: {ipheader.Protocol}");
                            break;
                    }
                }

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
        }        public bool HasOptions => byHeaderLength > 20;
        public byte OptionsLength => (byte)(byHeaderLength > 20 ? byHeaderLength - 20 : 0);
    }

    public class TCPHeader
    {
        private ushort usSourcePort;
        private ushort usDestinationPort;
        private uint uiSequenceNumber;
        private uint uiAcknowledgmentNumber;
        private byte byHeaderLengthAndFlags;
        private byte byFlags;
        private ushort usWindowSize;
        private short sChecksum;
        private ushort usUrgentPointer;
        private byte byHeaderLength;
        private ushort usDataLength;
        private byte[] byTCPData;

        public TCPHeader(byte[] byBuffer, int nReceived)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                uiSequenceNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());
                uiAcknowledgmentNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());
                
                byHeaderLengthAndFlags = binaryReader.ReadByte();
                byFlags = binaryReader.ReadByte();
                
                usWindowSize = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                sChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usUrgentPointer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                byHeaderLength = (byte)((byHeaderLengthAndFlags >> 4) * 4);
                usDataLength = (ushort)(nReceived - byHeaderLength);

                if (usDataLength > 0 && usDataLength <= nReceived - byHeaderLength)
                {
                    byTCPData = new byte[usDataLength];
                    Array.Copy(byBuffer, byHeaderLength, byTCPData, 0, usDataLength);
                }
                else
                {
                    byTCPData = new byte[0];
                    usDataLength = 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[TCP ОШИБКА] " + ex.Message);
                byTCPData = new byte[0];
            }
        }

        public ushort SourcePort => usSourcePort;
        public ushort DestinationPort => usDestinationPort;
        public uint SequenceNumber => uiSequenceNumber;
        public uint AcknowledgmentNumber => uiAcknowledgmentNumber;
        public byte HeaderLength => byHeaderLength;
        public ushort WindowSize => usWindowSize;
        public short Checksum => sChecksum;
        public ushort UrgentPointer => usUrgentPointer;
        public ushort DataLength => usDataLength;
        public byte[] Data => byTCPData;

        public string FlagsDescription
        {
            get
            {
                var flags = new List<string>();
                if ((byFlags & 0x01) != 0) flags.Add("FIN");
                if ((byFlags & 0x02) != 0) flags.Add("SYN");
                if ((byFlags & 0x04) != 0) flags.Add("RST");
                if ((byFlags & 0x08) != 0) flags.Add("PSH");
                if ((byFlags & 0x10) != 0) flags.Add("ACK");
                if ((byFlags & 0x20) != 0) flags.Add("URG");
                if ((byFlags & 0x40) != 0) flags.Add("ECE");
                if ((byFlags & 0x80) != 0) flags.Add("CWR");
                return string.Join(", ", flags);
            }
        }
    }

    public class UDPHeader
    {
        private ushort usSourcePort;
        private ushort usDestinationPort;
        private ushort usLength;
        private short sChecksum;
        private ushort usDataLength;
        private byte[] byUDPData;

        public UDPHeader(byte[] byBuffer, int nReceived)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                sChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                usDataLength = (ushort)(usLength - 8); // UDP заголовок 8 байт

                if (usDataLength > 0 && usDataLength <= nReceived - 8)
                {
                    byUDPData = new byte[usDataLength];
                    Array.Copy(byBuffer, 8, byUDPData, 0, usDataLength);
                }
                else
                {
                    byUDPData = new byte[0];
                    usDataLength = 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[UDP ОШИБКА] " + ex.Message);
                byUDPData = new byte[0];
            }
        }

        public ushort SourcePort => usSourcePort;
        public ushort DestinationPort => usDestinationPort;
        public ushort Length => usLength;
        public short Checksum => sChecksum;
        public ushort DataLength => usDataLength;
        public byte[] Data => byUDPData;
    }

    public class DNSHeader
    {
        private ushort usTransactionID;
        private ushort usFlags;
        private ushort usQuestionCount;
        private ushort usAnswerCount;
        private ushort usAuthorityCount;
        private ushort usAdditionalCount;
        private List<string> questions;

        public DNSHeader(byte[] byBuffer, int nReceived)
        {
            questions = new List<string>();
            
            try
            {
                if (nReceived < 12) return; // минимальный размер DNS заголовка

                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                usTransactionID = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usFlags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usQuestionCount = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usAnswerCount = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usAuthorityCount = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usAdditionalCount = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                // Парсим вопросы DNS
                try
                {
                    for (int i = 0; i < usQuestionCount && memoryStream.Position < nReceived - 4; i++)
                    {
                        string domainName = ParseDomainName(byBuffer, ref memoryStream);
                        if (!string.IsNullOrEmpty(domainName))
                        {
                            ushort qType = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                            ushort qClass = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                            
                            string qTypeStr = qType switch
                            {
                                1 => "A",
                                2 => "NS",
                                5 => "CNAME",
                                15 => "MX",
                                28 => "AAAA",
                                _ => qType.ToString()
                            };
                            
                            questions.Add($"{domainName} (Type: {qTypeStr}, Class: {qClass})");
                        }
                    }
                }
                catch
                {
                    // Если не удается парсить вопросы, просто продолжаем
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[DNS ОШИБКА] " + ex.Message);
            }
        }

        private string ParseDomainName(byte[] buffer, ref MemoryStream stream)
        {
            var parts = new List<string>();
            
            try
            {
                while (stream.Position < stream.Length)
                {
                    byte length = (byte)stream.ReadByte();
                    if (length == 0) break;
                    
                    if (length > 63) // Сжатое имя
                    {
                        stream.Position--; // Возвращаемся
                        stream.Position += 2; // Пропускаем точку сжатия
                        break;
                    }
                    
                    if (stream.Position + length > stream.Length) break;
                    
                    byte[] labelBytes = new byte[length];
                    stream.Read(labelBytes, 0, length);
                    parts.Add(Encoding.ASCII.GetString(labelBytes));
                }
            }
            catch
            {
                return "";
            }
            
            return string.Join(".", parts);
        }

        public ushort TransactionID => usTransactionID;
        public bool IsResponse => (usFlags & 0x8000) != 0;
        public byte Opcode => (byte)((usFlags >> 11) & 0x0F);
        public bool AuthoritativeAnswer => (usFlags & 0x0400) != 0;
        public bool Truncated => (usFlags & 0x0200) != 0;
        public bool RecursionDesired => (usFlags & 0x0100) != 0;
        public bool RecursionAvailable => (usFlags & 0x0080) != 0;
        public byte ResponseCode => (byte)(usFlags & 0x000F);
        public ushort QuestionCount => usQuestionCount;
        public ushort AnswerCount => usAnswerCount;
        public ushort AuthorityCount => usAuthorityCount;
        public ushort AdditionalCount => usAdditionalCount;
        public List<string> Questions => questions;
    }
}

