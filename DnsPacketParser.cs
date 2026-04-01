using System;
using System.Collections.Generic;
using System.Text;

namespace AdShieldNet;

public class DnsPacketParser
{
    // A more extensive list of mobile and general ad networks, analytics, and tracking domains
    private readonly string[] _blockedDomains = new string[]
    {
        "doubleclick.net",
        "google-analytics.com",
        "googlesyndication.com",
        "googleadservices.com",
        "applovin.com",
        "vungle.com",
        "taboola.com",
        "unityads.unity3d.com",
        "appsflyer.com",
        "amazon-adsystem.com",
        "adcolony.com",
        "chartboost.com",
        "adjust.com",
        "inmobi.com",
        "ironsrc.com",
        "flurry.com",
        "branch.io",
        "kochava.com",
        "singular.net",
        "graph.facebook.com",    // Facebook Tracking
        "connect.facebook.net",
        "ads.tiktok.com",        // TikTok Ads
        "analytics.tiktok.com",
        "byteoversea.com",       // ByteDance Analytics
        "bingads.microsoft.com", // Bing Ads
        "bat.bing.com",
        "criteo.com",
        "outbrain.com"
    };

    // Return the extracted domain additionally via an out parameter
    public bool IsBlocked(byte[] packet, int length, out string? domain)
    {
        domain = null;

        // Minimum size: IPv4 (20) + UDP (8) + DNS Header (12)
        if (length < 40) return false;

        // Check if IPv4 (first nibble is 4)
        if ((packet[0] >> 4) != 4) return false;

        int ipHeaderLength = (packet[0] & 0x0F) * 4;
        
        // Protocol 17 = UDP
        if (packet[9] != 17) return false;

        int udpStart = ipHeaderLength;
        if (udpStart + 8 > length) return false;

        int destPort = ((packet[udpStart + 2] << 8) | packet[udpStart + 3]);
        if (destPort != 53) return false;

        int dnsStart = udpStart + 8;
        if (dnsStart + 12 > length) return false;

        int questionStart = dnsStart + 12;
        domain = ExtractDomain(packet, questionStart, length, out _);

        if (!string.IsNullOrEmpty(domain))
        {
            // Verify if domain EXACTLY matches OR is a sub-domain of any blocked list item
            foreach (var blocked in _blockedDomains)
            {
                if (domain.Equals(blocked, StringComparison.OrdinalIgnoreCase) ||
                    domain.EndsWith("." + blocked, StringComparison.OrdinalIgnoreCase))
                {
                    System.Diagnostics.Debug.WriteLine($"AdShield: Blocked DNS query for {domain} (Matched: {blocked})");
                    return true;
                }
            }
        }

        return false; 
    }

    private string? ExtractDomain(byte[] packet, int offset, int length, out int newOffset)
    {
        var sb = new StringBuilder();
        newOffset = offset;
        
        try
        {
            while (newOffset < length)
            {
                int labelLen = packet[newOffset++];
                if (labelLen == 0) break;
                
                if ((labelLen & 0xC0) == 0xC0) 
                {
                    newOffset++;
                    break;
                }

                if (sb.Length > 0) sb.Append('.');
                
                for (int i = 0; i < labelLen && newOffset < length; i++)
                {
                    sb.Append((char)packet[newOffset++]);
                }
            }
            return sb.ToString();
        }
        catch
        {
            return null;
        }
    }
}
