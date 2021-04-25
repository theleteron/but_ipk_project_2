# IPK Sniffer 2021

## Run
To run sniffer app you can use
```
sudo make run arguments="[options]"
```
or call its binary (**binary is not part of the archive due to size limitations in WIS**)
```
sudo ./ipk-sniffer [options]
```
List of possible `[options]`
```
Options:
  -i, --interface <interface>  Select which interface should this program listen to
  -p, --port <port>            Select the port you are interested in [default: 1]
  -t, --tcp                    Show TCP packets
  -u, --udp                    Show UDP packets
  --arp                        Show ARP frame
  --icmp                       Show ICMPv4 & ICMPv6 packets
  --n <n>                      Number of packet you want to capture [default: 1]
  --version                    Show version information
  -?, -h, --help               Show help and usage information
  ```

## Build
To instal dependencies use
```
make install
```
To build stand-alone binary file you can use following command  
that will create `ipk-sniffer` binary **(requires [warp](https://github.com/dgiagio/warp))**
```
make publish
```

## Implementation progress
- [x] Arguments parsing
- [x] Print all availiable devices when used withou arguments or with `-i`, `--interface` only
- [x] Packet capturing
   - [x] Number of packets requested
   - [x] Port filter
   - [x] TCP
   - [x] UDP
   - [x] ARP
   - [x] ICMP

## Structure
- `README.md` - this file
- `Makefile` - to make build and run easier
- `ipk-sniffer` - pre-prepared binary builded from this code (**binary is not part of the archive due to size limitations in WIS**)
- `src/ipk-sniffer/`
    - `Program.cs` - ipk-sniffer program source code
    - `ipk-sniffer.csproj` - project file