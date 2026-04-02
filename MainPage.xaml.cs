namespace AdShieldNet;

public partial class MainPage : ContentPage
{
    private readonly IVpnHandler _vpnHandler;
    private bool _isVpnActive = false;

    public MainPage(IVpnHandler vpnHandler)
    {
        InitializeComponent();
        _vpnHandler = vpnHandler;
        _vpnHandler.BlockedCountChanged += OnBlockedCountChanged;
        _vpnHandler.VpnStopped += OnVpnStopped;
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _vpnHandler.BlockedCountChanged -= OnBlockedCountChanged;
        _vpnHandler.VpnStopped -= OnVpnStopped;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _vpnHandler.BlockedCountChanged -= OnBlockedCountChanged;
        _vpnHandler.BlockedCountChanged += OnBlockedCountChanged;
        _vpnHandler.VpnStopped -= OnVpnStopped;
        _vpnHandler.VpnStopped += OnVpnStopped;
    }

    private void OnBlockedCountChanged(object? sender, int count)
    {
        MainThread.BeginInvokeOnMainThread(() =>
            BlockedAdsLabel.Text = $"Blockierte Werbung: {count}");
    }

    private void OnVpnStopped(object? sender, EventArgs e)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            _isVpnActive = false;
            StatusLabel.Text = "Schutz ist inaktiv";
            StatusLabel.TextColor = Color.FromArgb("#aaaaaa");
            ToggleVpnButton.TextColor = Color.FromArgb("#555555");
            ToggleVpnButton.BorderColor = Color.FromArgb("#333333");
            BlockedAdsLabel.Text = "Blockierte Werbung: 0";
        });
    }

    private void OnToggleVpnClicked(object? sender, EventArgs e)
    {
        _isVpnActive = !_isVpnActive;

        if (_isVpnActive)
        {
            StatusLabel.Text = "Schutz ist aktiv";
            StatusLabel.TextColor = Colors.LightGreen;
            ToggleVpnButton.TextColor = Colors.LightGreen;
            ToggleVpnButton.BorderColor = Colors.LightGreen;
            _vpnHandler.StartVpn();
        }
        else
        {
            StatusLabel.Text = "Schutz ist inaktiv";
            StatusLabel.TextColor = Color.FromArgb("#aaaaaa");
            ToggleVpnButton.TextColor = Color.FromArgb("#555555");
            ToggleVpnButton.BorderColor = Color.FromArgb("#333333");
            BlockedAdsLabel.Text = "Blockierte Werbung: 0";
            _vpnHandler.StopVpn();
        }
    }
}
