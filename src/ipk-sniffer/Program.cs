using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using SharpPcap;

namespace IPKSniffer
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {            // Setup arguments
            var command = new RootCommand(description: "IPK Packet Sniffer");

            command.Add(new Option<string>(
                    new[] { "--interface", "-i" },
                    description: "Select which interface should this program listen to"
                ));
            command.Add(new Option<int>(
                    new[] { "--port", "-p" },
                    description: "Select the port you are interested in"
                ));
            command.Add(new Option<bool>(
                    new[] { "--tcp", "-t"},
                    description: "Show TCP packets"
                ));
            command.Add(new Option<bool>(
                    new[] { "--udp", "-u"},
                    description: "Show UDP packets"
                ));
            command.Add(new Option<bool>(
                    new[] { "--arp"},
                    description: "Show ARP frame"
                ));
            command.Add(new Option<bool>(
                    new[] { "--icmp"},
                    description: "Show ICMPv4 & ICMPv6 packets"
                ));

            command.Handler = CommandHandler.Create<string, int, bool, bool, bool, bool>(Execute);
            return await command.InvokeAsync(args);
        }

        public static void Execute(string lInterface, int lPort, bool lTCP, bool lUDP, bool lARP, bool lICMP)
        {
            Console.WriteLine($"Entered: {lInterface} {lPort} {lTCP} {lUDP} {lARP} {lICMP}");
        }
    }
}
