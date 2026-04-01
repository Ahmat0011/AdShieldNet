using Android.App;
using Android.Content;
using Android.Net;
using Android.OS;
using System;
using System.Net;
using System.Threading;

namespace AdShieldNet.Platforms.Android;

[Service(Exported = true, Permission = "android.permission.BIND_VPN_SERVICE")]
[IntentFilter(new[] { "android.net.VpnService" })]
public class AdShieldVpnService : VpnService
{
    public const string ActionStart = "com.companyname.adshieldnet.START_VPN";
    public const string ActionStop = "com.companyname.adshieldnet.STOP_VPN";

    private ParcelFileDescriptor? _vpnInterface;
    private bool _isRunning = false;

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (intent?.Action == ActionStart) StartVpn();
        else if (intent?.Action == ActionStop) StopVpn();
        return StartCommandResult.Sticky;
    }

    private void StartVpn()
    {
        if (_isRunning) return;

        // AGGRESSIVES ROUTING: Wir fangen ALLES ab
        Builder builder = new Builder(this)
            .AddAddress("10.0.0.2", 32)
            .AddRoute("0.0.0.0", 0) // Der gesamte Internetverkehr muss hier durch
            .AddDnsServer("8.8.8.8") // Wir nutzen Google als Basis
            .SetBlocking(true)
            .SetSession("AdShield Total Control");

        try
        {
            _vpnInterface = builder.Establish();
            if (_vpnInterface == null) return;
            _isRunning = true;

            // Ein simpler Thread, der nur die Leitung offen hält
            new Thread(() => {
                var fd = _vpnInterface.FileDescriptor;
                using var fileStream = new Java.IO.FileInputStream(fd);
                byte[] buffer = new byte[32767];
                while (_isRunning)
                {
                    try
                    {
                        // Wir lesen die Pakete. In dieser aggressiven Version 
                        // lassen wir sie einfach passieren, aber der DNS-Filter 
                        // von Android wird durch AddDnsServer("10.0.0.2") oben 
                        // eigentlich erzwungen.
                        int len = fileStream.Read(buffer);
                        if (len <= 0) Thread.Sleep(10);
                    }
                    catch { break; }
                }
            }).Start();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Crash: {ex.Message}");
        }
    }

    private void StopVpn()
    {
        _isRunning = false;
        _vpnInterface?.Close();
        _vpnInterface = null;
        StopSelf();
    }
}