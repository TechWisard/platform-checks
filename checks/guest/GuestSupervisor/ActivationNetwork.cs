using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SessionContractExperiment;

internal static class ActivationNetwork
{
    internal sealed record Observation(int EndpointId, bool DnsSucceeded, bool TcpSucceeded, bool TlsSucceeded, int? ErrorHresult);
    // Fixed Microsoft-documented activation endpoints. No URLs, addresses,
    // certificate details, request bodies, credentials or responses are logged.
    private static readonly string[] Endpoints = { "activation.sls.microsoft.com", "activation-v2.sls.microsoft.com" };

    internal static async Task<Observation[]> Observe()
    {
        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(15));
        return await Task.WhenAll(Endpoints.Select((name, index) => ObserveEndpoint(name, index + 1, deadline.Token)));
    }

    private static async Task<Observation> ObserveEndpoint(string name, int endpointId, CancellationToken token)
    {
        bool dns = false, tcp = false, tls = false;
        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(name, token);
            if (addresses.Length == 0) throw new InvalidOperationException("activation_dns_empty");
            dns = true;
            using TcpClient client = new();
            await client.ConnectAsync(addresses, 443, token);
            tcp = true;
            using SslStream stream = new(client.GetStream(), false);
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = name,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            }, token);
            tls = stream.IsAuthenticated && stream.IsEncrypted;
            return new(endpointId, dns, tcp, tls, null);
        }
        catch (Exception error)
        {
            return new(endpointId, dns, tcp, tls, error.HResult);
        }
    }
}
