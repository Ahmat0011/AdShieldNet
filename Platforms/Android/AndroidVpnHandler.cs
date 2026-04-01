using Android.App;
using Android.Content;
using Android.Net;
using Microsoft.Maui.ApplicationModel;
using Application = Android.App.Application;

namespace AdShieldNet.Platforms.Android;

public class AndroidVpnHandler : IVpnHandler
{
    public const int VpnRequestCode = 0x0F;

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
        Application.Context.StartService(intent);
    }

    public void StopVpn()
    {
        var intent = new Intent(Application.Context, typeof(AdShieldVpnService));
        intent.SetAction(AdShieldVpnService.ActionStop);
        Application.Context.StartService(intent);
    }
}
