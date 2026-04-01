namespace AdShieldNet;

public partial class MainPage : ContentPage
{
    private readonly IVpnHandler _vpnHandler;
    private bool _isVpnActive = false;

    public MainPage(IVpnHandler vpnHandler)
    {
        InitializeComponent();
        _vpnHandler = vpnHandler; // Nur Zuweisung, KEINE Methodenausführung!
    }

    private void OnToggleVpnClicked(object sender, EventArgs e)
    {
        _isVpnActive = !_isVpnActive;

        if (_isVpnActive)
        {
            StatusLabel.Text = "Schutz ist aktiv";
            StatusLabel.TextColor = Colors.LightGreen;
            ToggleVpnButton.Text = "Schutz beenden";
            ToggleVpnButton.BackgroundColor = Colors.DarkRed;
            
            _vpnHandler.StartVpn(); // Motor starten
        }
        else
        {
            StatusLabel.Text = "Schutz ist inaktiv";
            StatusLabel.TextColor = Color.FromArgb("#aaaaaa");
            ToggleVpnButton.Text = "Schutz starten";
            ToggleVpnButton.BackgroundColor = Color.FromArgb("#28a745");
            
            _vpnHandler.StopVpn(); // Motor stoppen
        }
    }
}
