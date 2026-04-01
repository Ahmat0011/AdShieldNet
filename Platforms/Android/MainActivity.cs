using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using AdShieldNet.Platforms.Android;

namespace AdShieldNet;

[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTop, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);

        if (requestCode == AndroidVpnHandler.VpnRequestCode)
        {
            if (resultCode == Result.Ok)
            {
                AndroidVpnHandler.StartVpnServiceInternal();
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("VPN Permission denied by the user.");
            }
        }
    }
}
