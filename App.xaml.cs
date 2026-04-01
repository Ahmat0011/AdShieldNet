namespace AdShieldNet;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        // Die MainPage (inklusive injiziertem IVpnHandler) vom System auflösen lassen
        var mainPage = activationState?.Context.Services.GetRequiredService<MainPage>();
        return new Window(new NavigationPage(mainPage));
    }
}