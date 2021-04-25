using System;
using System.Text;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace IPKSniffer
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {           
            // Setup arguments
            var command = new RootCommand(description: "IPK Packet Sniffer")
            {
                new Option(
                    aliases: new[] { "--interface", "-i" },
                    description: "Select which interface should this program listen to",
                    argumentType: typeof(string),
                    arity: new ArgumentArity(0, 1)
                ),
                new Option<int>(
                    aliases: new[] { "--port", "-p" },
                    getDefaultValue: () => -1,
                    description: "Select the port you are interested in"
                ),
                new Option<bool>(
                    aliases: new[] { "--tcp", "-t"},
                    description: "Show TCP packets"
                ),
                new Option<bool>(
                    aliases: new[] { "--udp", "-u"},
                    description: "Show UDP packets"
                ),
                new Option<bool>(
                    aliases: new[] { "--arp"},
                    description: "Show ARP frame"
                ),
                new Option<bool>(
                    aliases: new[] { "--icmp"},
                    description: "Show ICMPv4 & ICMPv6 packets"
                ),
                new Option<int>(
                    aliases: new[] { "--n"},
                    getDefaultValue: () => 1,
                    description: "Number of packet you want to capture"
                )
            };

            command.Handler = CommandHandler.Create<string, int, bool, bool, bool, bool, int>((@interface, port, tcp, udp, arp, icmp, n) => 
            {
                if (@interface == "") 
                {
                    PrintDevices();
                } else {
                    ListenOnDevice(@interface, port, tcp, udp, arp, icmp, n);
                }       

                return 0;
            });

            return await command.InvokeAsync(args);
        }

        private static void ListenOnDevice(string @interface, int port, bool tcp, bool udp, bool arp, bool icmp, int toCapture) 
        {
            // Set protocols (filter)
            if (!tcp && !udp && !arp && !icmp)
            {
                tcp = true;
                udp = true;
                arp = true;
                icmp = true;
            }
            // Get list of interfaces availiable on this device
            var devices = CaptureDeviceList.Instance;
            // Get ID of the device specified by `-i | --interface` argument
            int deviceId = GetDeviceId(@interface);
            // Device not found
            if (deviceId < 0) 
            {
                Console.WriteLine($"Interface {@interface} not found on this device.");
            }

            // Select device
            var device = devices[deviceId];
            // Number of received packets
            int packetCounter = 0;
            bool caputreMore = true;

            // Event handler := Function to process arriving packets
            device.OnPacketArrival += new PacketArrivalEventHandler((object sender, CaptureEventArgs e) => 
            {
                if (packetCounter < toCapture)
                {
                    var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                    // Extract interesting packets
                    var ethernetPacket = packet.Extract<EthernetPacket>();
                    var ipv4Packet = packet.Extract<IPv4Packet>();
                    var ipv6Packet = packet.Extract<IPv6Packet>();
                    var arpPacket = packet.Extract<ArpPacket>();
                    var tcpPacket = packet.Extract<TcpPacket>();
                    var udpPacket = packet.Extract<UdpPacket>();
                    var icmp4Packet = packet.Extract<IcmpV4Packet>();
                    var icmp6Packet = packet.Extract<IcmpV6Packet>();
                    if (ipv4Packet != null) 
                    {
                        // IPv4 TCP Packet
                        if (tcpPacket != null && tcp) 
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv4Packet.SourceAddress} : {tcpPacket.SourcePort} > {ipv4Packet.DestinationAddress} : {tcpPacket.DestinationPort}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        } 
                        // IPv4 UDP Packet
                        else if (udpPacket != null && udp) 
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv4Packet.SourceAddress} : {udpPacket.SourcePort} > {ipv4Packet.DestinationAddress} : {udpPacket.DestinationPort}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        } 
                        // IPv4 ICMP Packet
                        else if (icmp4Packet != null && icmp)
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv4Packet.SourceAddress} > {ipv4Packet.DestinationAddress}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        }
                    } else if (ipv6Packet != null) 
                    {
                        // IPv6 TCP Packet
                        if (tcpPacket != null && tcp) 
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv6Packet.SourceAddress} : {tcpPacket.SourcePort} > {ipv6Packet.DestinationAddress} : {tcpPacket.DestinationPort}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        } 
                        // IPv6 UDP Packet
                        else if (udpPacket != null && udp) 
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv6Packet.SourceAddress} : {udpPacket.SourcePort} > {ipv6Packet.DestinationAddress} : {udpPacket.DestinationPort}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        } 
                        // IPv6 ICMP Packet
                        else if (icmp6Packet != null && icmp)
                        {
                            Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                            Console.Write($" {ipv6Packet.SourceAddress} > {ipv6Packet.DestinationAddress}, length {packet.TotalPacketLength} bytes\n");
                            Console.Write(PacketContent(packet));
                            packetCounter++;
                        }
                    } else if (arpPacket != null && arp) 
                    {
                        Console.Write($"{TimeInRFC3339(e.Packet.Timeval.Date)}");
                        Console.Write($" {arpPacket.SenderHardwareAddress} > {arpPacket.TargetHardwareAddress}, length {packet.TotalPacketLength} bytes\n");
                        Console.Write(PacketContent(packet));
                        packetCounter++;
                    }
                    if (packetCounter + 1 < toCapture) {
                        Console.Write($"\n----------------------------------------------------------------------------------------------\n");
                    }
                } else 
                {
                    caputreMore = false;
                    device.StopCapture();
                    device.Close();
                }
            });

            // Open device
            device.Open(
                mode: DeviceMode.Promiscuous,
                read_timeout: 1000
            );
            if (port > 0)
            {
                device.Filter = $"port {port}";
            }

            // Start capturing process
            device.StartCapture();

            // Closing condition
            while(caputreMore) {/*Console.WriteLine($"{packetCounter} < {toCapture}");*/};

            device.StopCapture();
            device.Close();
        }

        /// Inspired by PacketDotNet PrintHex() function
        /// https://github.com/chmorgan/packetnet
        private static string PacketContent(Packet packet)
        {
            var data = packet.BytesSegment.Bytes;
            var result = new StringBuilder();
            var hex = "";
            var ascii = "";
            double lines = 1;

            for (var i = 1; i < data.Length; i++) 
            {
                hex += data[i-1].ToString("x").PadLeft(2, '0') + " ";

                // Non-printable characters print as '.'
                if (data[i-1] < 0x21 || data[i-1] > 0x7e)
                {
                    ascii += ".";
                } else 
                {
                    ascii += Encoding.ASCII.GetString(new[] {data[i-1]});
                }
                
                // Add extra space for group splitting
                if (i%16 != 0 && i%8 == 0)
                {
                    hex += " ";
                    ascii += " ";
                }

                // Number (https://docs.microsoft.com/en-us/dotnet/api/system.string.padleft?view=net-5.0)
                // 0-15 (16 bytes) -> 16 bytes => 1 line
                // Ex. (32-16)/16 = 1*10 => 0x0010
                if (i % 16 == 0) 
                {
                    // Space between 0,1,2,4,8,16,...
                    if ((i/16) == lines) 
                    {
                        result.Append("\n");
                        lines = Math.Pow(2, (i/16));
                    }
                    result.Append($"0x{((i-16)/16*10).ToString().PadLeft(4, '0')}");
                    // Last line padding
                    if (i == data.Length) 
                    {
                        result.Append(" " + hex.PadRight(49, ' ') + " " + ascii + "\n");
                    } else 
                    {
                        result.Append(" " + hex + " " + ascii + "\n");
                    }
                    // Reset
                    hex = "";
                    ascii = "";
                }
            }

            return result.ToString();
        }

        private static string TimeInRFC3339(DateTime time)
        {
            // https://docs.microsoft.com/en-us/dotnet/api/system.xml.xmlconvert.tostring
            //return System.Xml.XmlConvert.ToString(time, System.Xml.XmlDateTimeSerializationMode.Utc);
            return time.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz");
        }

        private static int GetDeviceId(string @interface) 
        {
            // Get list of interfaces availiable on this device
            var devices = CaptureDeviceList.Instance;
            int i = 0;

            // Go throught the list and look for device that was specified in `-i | --interface`
            foreach (var device in devices) 
            {
                if (String.Compare(device.Name, @interface) == 0) 
                {
                    // Device found
                    return i;
                }
                i++;
            }

            // Device not found
            return -1;
        }

        private static void PrintDevices() {
            // Get list of interfaces availiable on this device
            var devices = CaptureDeviceList.Instance;

            // In case that no devices were found
            if (devices.Count < 1) 
            {
                Console.WriteLine($"No devices were found on this device");
                return;
            }

            // List all devices (name only)
            foreach (var device in devices) 
            {
                Console.WriteLine($"{device.Name}");
            }
        }
    }
}
