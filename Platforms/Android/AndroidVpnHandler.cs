using Android.App;
using Android.Content;
using Android.Net;
using Android.OS;
using Microsoft.Maui.ApplicationModel;
using Application = Android.App.Application;

namespace AdShieldNet.Platforms.Android;

public class AndroidVpnHandler : IVpnHandler
{
    public const int VpnRequestCode = 0x0F;

    public event EventHandler<int>? BlockedCountChanged
    {
        add => AdShieldVpnService.BlockedCountChanged += value;
        remove => AdShieldVpnService.BlockedCountChanged -= value;
    }

    public void StartVpn()
    {
        var intent = VpnService.Prepare(Application.Context);
        if (intent != null)
        {
            Platform.CurrentActivity?.StartActivityForResult(intent, VpnRequestCode);
        }
        else
        {
            StartVpnServiceInternal();
        }
    }

    public static void StartVpnServiceInternal()
    {
        var intent = new Intent(Application.Context, typeof(AdShieldVpnService));
        intent.SetAction(AdShieldVpnService.ActionStart);
#pragma warning disable CA1416
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            Application.Context.StartForegroundService(intent);
        else
            Application.Context.StartService(intent);
#pragma warning restore CA1416
    }

    public void StopVpn()
    {
        var intent = new Intent(Application.Context, typeof(AdShieldVpnService));
        intent.SetAction(AdShieldVpnService.ActionStop);
        Application.Context.StartService(intent);
    }
}
