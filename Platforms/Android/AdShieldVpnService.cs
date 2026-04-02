using Android.App;
using Android.Content;
using Android.Net;
using Android.OS;
using Android.Runtime;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AddressFamily = System.Net.Sockets.AddressFamily;
using ProtocolType = System.Net.Sockets.ProtocolType;
using Socket = System.Net.Sockets.Socket;
using SocketType = System.Net.Sockets.SocketType;

namespace AdShieldNet.Platforms.Android;

// [Register] gives the Android Callable Wrapper a stable, predictable Java class
// name so that the android:name in AndroidManifest.xml can reference it reliably.
// Without this attribute .NET for Android generates a hash-based name that may
// change between builds.
[Register("com/companyname/adshieldnet/AdShieldVpnService")]
public class AdShieldVpnService : VpnService
{
    public const string ActionStart = "com.companyname.adshieldnet.START_VPN";
    public const string ActionStop = "com.companyname.adshieldnet.STOP_VPN";
    private const string ChannelId = "adshield_channel";
    private const int NotifId = 1;

    private const string PrimaryDnsServer = "8.8.8.8";
    private const string FallbackDnsServer = "1.1.1.1";

    private ParcelFileDescriptor? _vpnInterface;
    private CancellationTokenSource? _cts;
    private readonly DnsPacketParser _parser = new();
    private static int _blockedCount;
    private int _stoppedFlag; // used with Interlocked to prevent double-stop

    public static int BlockedCount => _blockedCount;
    public static event EventHandler<int>? BlockedCountChanged;
    public static event EventHandler? VpnStopped;

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (intent?.Action == ActionStart) StartVpnService();
        else if (intent?.Action == ActionStop) StopVpnService();
        else StopSelf(); // Restarted by Android with null intent — nothing to do
        return StartCommandResult.NotSticky;
    }

    private void StartVpnService()
    {
        if (_vpnInterface != null) return;

        // Reset the stop-guard so a subsequent stop call is handled correctly.
        Interlocked.Exchange(ref _stoppedFlag, 0);

        StartForegroundNotification();

        // Route only traffic destined for 10.0.0.2 (our fake DNS server) through the VPN.
        // All other traffic flows through the real network so websites load normally.
        var builder = new Builder(this)
            .AddAddress("10.0.0.2", 32)
            .AddDnsServer("10.0.0.2")
            .AddRoute("10.0.0.2", 32)
            .SetMtu(1500)
            .SetSession("AdShield");

        _vpnInterface = builder.Establish();
        if (_vpnInterface == null)
        {
            StopForegroundCompat();
            return;
        }

        Interlocked.Exchange(ref _blockedCount, 0);
        _cts = new CancellationTokenSource();
        Task.Run(() => RunPacketLoop(_cts.Token));
    }

    private void StopVpnService()
    {
        // Guard: ensure we only execute stop logic once even if called from both
        // OnStartCommand(ActionStop) and OnDestroy() at the same time.
        if (Interlocked.Exchange(ref _stoppedFlag, 1) != 0) return;

        _cts?.Cancel();
        _cts = null;
        _vpnInterface?.Close();
        _vpnInterface = null;
        StopForegroundCompat();
        VpnStopped?.Invoke(this, EventArgs.Empty);
        StopSelf();
    }

#pragma warning disable CA1416, CA1422
    private void StopForegroundCompat()
    {
        if (Build.VERSION.SdkInt >= BuildVersionCodes.N)
            StopForeground(StopForegroundFlags.Remove);
        else
            StopForeground(true);
    }

    private void StartForegroundNotification()
    {
        Notification notification;
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
        {
            var channel = new NotificationChannel(ChannelId, "AdShield VPN", NotificationImportance.Low);
            channel.Description = "AdShield DNS-Filter";
            var nm = (NotificationManager?)GetSystemService(NotificationService);
            nm?.CreateNotificationChannel(channel);
            notification = new Notification.Builder(this, ChannelId)
                .SetContentTitle("AdShield ist aktiv")
                .SetContentText("DNS-Filter schützt Ihr Gerät")
                .SetSmallIcon(global::Android.Resource.Drawable.IcDialogInfo)
                .SetOngoing(true)
                .Build();
        }
        else
        {
#pragma warning disable CS0618
            notification = new Notification.Builder(this)
#pragma warning restore CS0618
                .SetContentTitle("AdShield ist aktiv")
                .SetContentText("DNS-Filter schützt Ihr Gerät")
                .SetSmallIcon(global::Android.Resource.Drawable.IcDialogInfo)
                .SetOngoing(true)
                .Build();
        }

        CallStartForeground(notification);
    }

    private void CallStartForeground(Notification notification)
    {
        // Android 14+ (API 34) requires startForeground() to pass the foreground service
        // type that was declared in the manifest (connectedDevice).  The typed
        // 3-argument overload is available from API 29, so we use it there and above.
        // On older OS versions the 2-argument overload is used.
        const global::Android.Content.PM.ForegroundService ForegroundServiceTypeConnectedDevice = (global::Android.Content.PM.ForegroundService)0x10; // ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        if (Build.VERSION.SdkInt >= BuildVersionCodes.Q)
            StartForeground(NotifId, notification, ForegroundServiceTypeConnectedDevice);
        else
            StartForeground(NotifId, notification);
    }
#pragma warning restore CA1416, CA1422

    private void RunPacketLoop(CancellationToken token)
    {
        var fd = _vpnInterface?.FileDescriptor;
        if (fd == null) return;

        using var input = new Java.IO.FileInputStream(fd);
        using var output = new Java.IO.FileOutputStream(fd);
        byte[] buffer = new byte[32767];

        while (!token.IsCancellationRequested)
        {
            try
            {
                int len = input.Read(buffer);
                if (len <= 0)
                {
                    Thread.Sleep(10);
                    continue;
                }

                if (!IsDnsQuery(buffer, len)) continue;

                bool blocked = _parser.IsBlocked(buffer, len, out _);

                int ipHdrLen = (buffer[0] & 0x0F) * 4;
                int dnsOffset = ipHdrLen + 8;
                int dnsLen = len - dnsOffset;
                if (dnsLen <= 0) continue;

                byte[] dnsPayload = new byte[dnsLen];
                Array.Copy(buffer, dnsOffset, dnsPayload, 0, dnsLen);

                byte[]? dnsResponse;
                if (blocked)
                {
                    int count = Interlocked.Increment(ref _blockedCount);
                    BlockedCountChanged?.Invoke(null, count);
                    dnsResponse = MakeNxDomain(dnsPayload);
                }
                else
                {
                    dnsResponse = ForwardDns(dnsPayload);
                }

                // If forwarding failed, reply with SERVFAIL so the client fails fast
                // instead of waiting for a timeout that makes legitimate sites appear broken.
                if (dnsResponse == null)
                    dnsResponse = MakeServFail(dnsPayload);

                byte[]? responsePacket = WrapInIpUdp(buffer, len, dnsResponse);
                if (responsePacket != null)
                    output.Write(responsePacket);
            }
            catch when (!token.IsCancellationRequested)
            {
                Thread.Sleep(50);
            }
            catch
            {
                break;
            }
        }

        // Packet loop exited without explicit cancellation — stop the service cleanly
        if (!token.IsCancellationRequested)
            StopSelf();
    }

    private static bool IsDnsQuery(byte[] p, int len)
    {
        if (len < 40) return false;
        if ((p[0] >> 4) != 4) return false;                    // Must be IPv4
        int ihl = (p[0] & 0x0F) * 4;
        if (p[9] != 17) return false;                          // Must be UDP
        if (ihl + 4 > len) return false;
        return ((p[ihl + 2] << 8) | p[ihl + 3]) == 53;        // Destination port 53
    }

    private byte[]? ForwardDns(byte[] query)
    {
        // Try primary DNS first, then fall back to a secondary server
        return ForwardDnsTo(query, PrimaryDnsServer)
            ?? ForwardDnsTo(query, FallbackDnsServer);
    }

    private byte[]? ForwardDnsTo(byte[] query, string server)
    {
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            // File descriptors on Android are always small non-negative integers,
            // so truncating to int32 is safe here. Any failure is caught below.
            Protect(sock.Handle.ToInt32());
            sock.SendTimeout = 2000;
            sock.ReceiveTimeout = 2000;

            var endpoint = new IPEndPoint(IPAddress.Parse(server), 53);
            sock.SendTo(query, endpoint);

            var buf = new byte[4096];
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            int n = sock.ReceiveFrom(buf, ref remote);
            if (n <= 0) return null;

            var result = new byte[n];
            Array.Copy(buf, result, n);
            return result;
        }
        catch
        {
            return null;
        }
    }

    // Craft a DNS NXDOMAIN response from the original query payload
    private static byte[] MakeNxDomain(byte[] query)
    {
        var response = new byte[query.Length];
        Array.Copy(query, response, query.Length);
        // QR=1 (response), preserve OPCODE and RD, clear AA and TC
        // 0x80 sets QR=1; 0xF9 (11111001) clears bits 2 (AA) and 1 (TC) while preserving RD (bit 0)
        response[2] = (byte)((query[2] | 0x80) & 0xF9);
        // RA=1, RCODE=3 (NXDOMAIN)
        response[3] = 0x83;
        // Zero out answer / authority / additional counts
        response[6] = response[7] = 0;
        response[8] = response[9] = 0;
        response[10] = response[11] = 0;
        return response;
    }

    // Craft a DNS SERVFAIL response from the original query payload
    private static byte[] MakeServFail(byte[] query)
    {
        var response = new byte[query.Length];
        Array.Copy(query, response, query.Length);
        // QR=1 (response), preserve OPCODE and RD, clear AA and TC
        response[2] = (byte)((query[2] | 0x80) & 0xF9);
        // RA=1, RCODE=2 (SERVFAIL)
        response[3] = 0x82;
        // Zero out answer / authority / additional counts
        response[6] = response[7] = 0;
        response[8] = response[9] = 0;
        response[10] = response[11] = 0;
        return response;
    }

    // Wrap a DNS payload in an IPv4/UDP packet, swapping source/destination from the original query
    private static byte[]? WrapInIpUdp(byte[] orig, int origLen, byte[] dns)
    {
        int ihl = (orig[0] & 0x0F) * 4;
        if (ihl + 8 > origLen) return null;

        int udpLen = 8 + dns.Length;
        int ipLen = 20 + udpLen;
        var pkt = new byte[ipLen];

        // IPv4 header (no options)
        pkt[0] = 0x45;                           // Version=4, IHL=5
        pkt[1] = 0;
        pkt[2] = (byte)(ipLen >> 8);
        pkt[3] = (byte)(ipLen & 0xFF);
        pkt[4] = pkt[5] = 0;                    // ID=0 (acceptable; Don't Fragment flag is set so no reassembly)
        pkt[6] = 0x40; pkt[7] = 0;             // Don't Fragment
        pkt[8] = 64;                             // TTL
        pkt[9] = 17;                             // Protocol: UDP
        pkt[10] = pkt[11] = 0;                  // Checksum (filled below)

        // Swap src ↔ dst IP
        pkt[12] = orig[16]; pkt[13] = orig[17]; pkt[14] = orig[18]; pkt[15] = orig[19];
        pkt[16] = orig[12]; pkt[17] = orig[13]; pkt[18] = orig[14]; pkt[19] = orig[15];

        // UDP header: swap src ↔ dst port
        pkt[20] = orig[ihl + 2]; pkt[21] = orig[ihl + 3]; // src = orig dst port (53)
        pkt[22] = orig[ihl + 0]; pkt[23] = orig[ihl + 1]; // dst = orig src port
        pkt[24] = (byte)(udpLen >> 8);
        pkt[25] = (byte)(udpLen & 0xFF);
        pkt[26] = pkt[27] = 0;                  // UDP checksum disabled

        Array.Copy(dns, 0, pkt, 28, dns.Length);

        // IPv4 header checksum
        int sum = 0;
        for (int i = 0; i < 20; i += 2)
            sum += (pkt[i] << 8) | pkt[i + 1];
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        sum = ~sum & 0xFFFF;
        pkt[10] = (byte)(sum >> 8);
        pkt[11] = (byte)(sum & 0xFF);

        return pkt;
    }

    public override void OnDestroy()
    {
        StopVpnService();
        base.OnDestroy();
    }
}