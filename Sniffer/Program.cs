using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SnifferTesting
{
    class Program
    {
        static void Main(string[] args)
        {   
            string? ipadress = "255.255.255.255";
            bool flag = true;
            Console.Write("Enter local ip-adress here: ");
            while(flag)
            {
                ipadress = Console.ReadLine();
                Regex regex = new Regex(@"^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$");
                if (!string.IsNullOrWhiteSpace(ipadress) && regex.IsMatch(ipadress))
                {
                    flag = false;
                }
            }
            try
            {
                if (!string.IsNullOrWhiteSpace(ipadress))
                {
                    Sniffer sniffer = new Sniffer();
                    sniffer.startSocket(ipadress);
                    Console.WriteLine("Сниффер запущен. Нажмите Enter для выхода...");
                    Console.ReadLine();
                }

            }
            catch(Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message); 
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
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);
                IPHeader ipheader = new IPHeader(byteData, nReceived);

                Console.WriteLine("Пакет получен!");

                Console.WriteLine($"Source: {ipheader.SourceAddress}, Dest: {ipheader.DestinationAddress}");

                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message);  
            }
        }
    }

    public class IPHeader
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
                byHeaderLength = byVersionAndHeaderLength;

                byHeaderLength <<= 4;
                byHeaderLength >>= 4;
                byHeaderLength *= 4;

                Array.Copy(byBuffer, byHeaderLength, byIPData, 0, usTotalLength - byHeaderLength);
            }
            catch(Exception ex)
            {
                Console.WriteLine("[ERROR] " + ex.Message); 
            }
        }

        public IPAddress SourceAddress => new IPAddress(uiSourcelIPAdress);
        public IPAddress DestinationAddress => new IPAddress(uiDestinationIPAdress);
    }
}

