namespace AdShieldNet;

public interface IVpnHandler
{
    void StartVpn();
    void StopVpn();
    event EventHandler<int>? BlockedCountChanged;
    event EventHandler? VpnStopped;
}
