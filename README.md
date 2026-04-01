# AdShieldNet

AdShieldNet is a high-performance, stealthy DNS-based adblocker for Android built with .NET 10 MAUI.

## Features
- **DNS Sinkholing**: Precise NXDOMAIN-based filtering for blocked domains.
- **Packet Forwarding**: Flawless, checksum-compliant forwarding for legitimate traffic.
- **VPN Service**: Operates at the system level for comprehensive protection.
- **Power Efficient**: Designed for minimal battery impact.

## Project Structure
- `AdShieldNet.csproj`: Main project file.
- `DnsPacketParser.cs`: Handles DNS packet analysis and modification.
- `Platforms/Android/AdShieldVpnService.cs`: Core VPN service implementation for Android.
- `IVpnHandler.cs`: Interface for VPN cross-platform handling.

## Development
- Required: .NET 10 SDK
- IDE: Visual Studio 2022 or VS Code with .NET MAUI extensions.

## License
MIT
