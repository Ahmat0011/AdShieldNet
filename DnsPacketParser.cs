using System;
using System.Collections.Generic;
using System.Text;

namespace AdShieldNet;

public class DnsPacketParser
{
    // Comprehensive list of ad networks, analytics, and tracking domains.
    // Sub-domain matching is applied, so e.g. "doubleclick.net" also blocks "ad.doubleclick.net".
    private readonly string[] _blockedDomains = new string[]
    {
        // Google advertising & analytics
        "doubleclick.net",
        "google-analytics.com",
        "googlesyndication.com",
        "googleadservices.com",
        "googletagmanager.com",
        "googletagservices.com",
        "analytics.google.com",
        "adservice.google.com",
        "2mdn.net",              // Google's ad-delivery CDN

        // Major programmatic ad networks
        "appnexus.com",
        "adnxs.com",             // AppNexus / Xandr
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "smartadserver.com",
        "adform.net",
        "advertising.com",
        "adsrvr.org",            // The Trade Desk
        "tradedesk.com",
        "mediamath.com",
        "mathtag.com",
        "indexexchange.com",
        "lijit.com",             // Sovrn
        "33across.com",
        "bidswitch.net",
        "yieldmo.com",
        "spotxchange.com",
        "spotx.tv",
        "freewheel.tv",
        "connatix.com",
        "media.net",
        "moatads.com",
        "moatpixel.com",

        // Analytics & data-collection platforms
        "quantserve.com",
        "scorecardresearch.com",
        "omtrdc.net",            // Adobe Analytics
        "demdex.net",            // Adobe Audience Manager
        "2o7.net",               // Adobe Analytics (legacy)
        "everesttech.net",
        "mixpanel.com",
        "amplitude.com",
        "segment.io",
        "segment.com",
        "hotjar.com",
        "mouseflow.com",
        "fullstory.com",
        "heap.io",
        "crazyegg.com",
        "newrelic.com",
        "nr-data.net",           // New Relic browser agent

        // Mobile ad networks & SDKs
        "applovin.com",
        "vungle.com",
        "adcolony.com",
        "chartboost.com",
        "ironsrc.com",
        "inmobi.com",
        "tapjoy.com",
        "digitalturbine.com",
        "fyber.com",
        "mintegral.com",
        "mobvista.com",
        "loopme.com",
        "startapp.com",
        "mopub.com",
        "unityads.unity3d.com",

        // Attribution & analytics SDKs
        "appsflyer.com",
        "adjust.com",
        "kochava.com",
        "singular.net",
        "branch.io",
        "flurry.com",

        // Social-media tracking pixels & ad delivery
        "graph.facebook.com",
        "connect.facebook.net",
        "an.facebook.com",
        "ads.tiktok.com",
        "analytics.tiktok.com",
        "byteoversea.com",

        // Amazon DSP / display ads
        "amazon-adsystem.com",
        "sizmek.com",

        // Microsoft / Bing advertising
        "bingads.microsoft.com",
        "bat.bing.com",
        "clarity.ms",            // Microsoft Clarity heat-mapping

        // Retargeting & content-recommendation
        "criteo.com",
        "outbrain.com",
        "taboola.com",
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
