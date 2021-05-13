all : clean restore build publish

install:
	cd src/ipk-sniffer && \
	dotnet add package SharpPcap --version 5.4.0
	cd src/ipk-sniffer && \
	dotnet add package System.CommandLine --version 2.0.0-beta1.21216.1
	cd src/ipk-sniffer && \
	dotnet add package PacketDotNet --version 1.2.0

clean:
	cd src/ipk-sniffer && \
	dotnet clean

restore:
	cd src/ipk-sniffer && \
	dotnet restore

build:
	cd src/ipk-sniffer && \
	dotnet build

publish:
	cd src/ipk-sniffer && \
	dotnet publish -c Release -r linux-x64;
# Warp CLI tool for .NET Core app deploy
# https://github.com/dgiagio/warp#linux-1
	warp-packer --arch linux-x64 --input_dir src/ipk-sniffer/bin/Release/netcoreapp3.1/linux-x64/publish --exec ipk-sniffer --output ipk-sniffer

run:
	cd src/ipk-sniffer && \
	dotnet run $(arguments)