using Microsoft.Extensions.Logging;

namespace AdShieldNet;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			});

#if DEBUG
		builder.Logging.AddDebug();
#endif

#if ANDROID
        builder.Services.AddSingleton<IVpnHandler, AdShieldNet.Platforms.Android.AndroidVpnHandler>();
#endif
        builder.Services.AddSingleton<MainPage>();

		return builder.Build();
	}
}
