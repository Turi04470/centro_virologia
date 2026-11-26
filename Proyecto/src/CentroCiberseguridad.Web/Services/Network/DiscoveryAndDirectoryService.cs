using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Transfer;

namespace CentroCiberseguridad.Web.Services.Network;

public sealed class DiscoveryAndDirectoryService : BackgroundService
{
    private readonly SqliteDatabaseService _db;
    private readonly CertificateAndZipService _certZip;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<DiscoveryAndDirectoryService> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public DiscoveryAndDirectoryService(
        SqliteDatabaseService db,
        CertificateAndZipService certZip,
        IHttpClientFactory httpFactory,
        ILogger<DiscoveryAndDirectoryService> logger)
    {
        _db = db;
        _certZip = certZip;
        _httpFactory = httpFactory;
        _logger = logger;
    }

    public static string GetLocalLanIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ua.Address))
                        return ua.Address.ToString();
                }
            }
        }
        catch { }
        return "127.0.0.1";
    }

    private static List<IPAddress> GetBroadcastAddresses()
    {
        var list = new List<IPAddress> { IPAddress.Broadcast };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null) continue;
                    var ipBytes = ua.Address.GetAddressBytes();
                    var maskBytes = ua.IPv4Mask.GetAddressBytes();
                    var bcast = new byte[4];
                    for (var i = 0; i < 4; i++) bcast[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
                    var bcastAddr = new IPAddress(bcast);
                    if (!list.Contains(bcastAddr)) list.Add(bcastAddr);
                }
            }
        }
        catch { }
        return list;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listenerTask = RunUdpListenerAsync(stoppingToken);
        var beaconTask = RunBeaconLoopAsync(stoppingToken);
        await Task.WhenAll(listenerTask, beaconTask);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { await SendBeaconAsync("offline"); } catch { }
        await base.StopAsync(cancellationToken);
    }

    private async Task RunBeaconLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await SendBeaconAsync("online");
                _db.MarkStaleNodesOffline(TimeSpan.FromSeconds(90));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error en ciclo de anuncio UDP");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task SendBeaconAsync(string status)
    {
        var cert = _certZip.GetLocalCertificate();
        var beacon = new
        {
            type = "CC-BEACON",
            protocolVersion = "2.0",
            nodeId = SqliteDatabaseService.LocalNodeId,
            teamNumber = SqliteDatabaseService.LocalTeamNumber,
            ip = GetLocalLanIp(),
            httpPort = SqliteDatabaseService.LocalHttpPort,
            httpsPort = (int?)null,
            status,
            algorithms = SqliteDatabaseService.OwnedAlgorithmCodes,
            certificateThumbprintSha256 = cert.ThumbprintSha256,
            timestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        var payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(beacon, JsonOpts));
        using var udp = new UdpClient { EnableBroadcast = true };
        foreach (var addr in GetBroadcastAddresses())
        {
            try
            {
                await udp.SendAsync(payload, payload.Length, new IPEndPoint(addr, SqliteDatabaseService.UdpDiscoveryPort));
            }
            catch { }
        }
    }

    private async Task RunUdpListenerAsync(CancellationToken ct)
    {
        UdpClient? listener = null;
        try
        {
            listener = new UdpClient();
            listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Client.Bind(new IPEndPoint(IPAddress.Any, SqliteDatabaseService.UdpDiscoveryPort));

            while (!ct.IsCancellationRequested)
            {
                var result = await listener.ReceiveAsync(ct);
                _ = Task.Run(() => HandleBeaconAsync(result.Buffer, result.RemoteEndPoint.Address.ToString()), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo abrir el puerto UDP {Port} para descubrimiento.", SqliteDatabaseService.UdpDiscoveryPort);
        }
        finally
        {
            listener?.Dispose();
        }
    }

    private async Task HandleBeaconAsync(byte[] buffer, string remoteIp)
    {
        try
        {
            if (buffer.Length > 1024) return;
            using var doc = JsonDocument.Parse(buffer);
            var root = doc.RootElement;
            if (root.GetProperty("type").GetString() != "CC-BEACON") return;
            if (root.GetProperty("protocolVersion").GetString() != "2.0") return;

            var nodeId = root.GetProperty("nodeId").GetString() ?? "";
            if (string.Equals(nodeId, SqliteDatabaseService.LocalNodeId, StringComparison.Ordinal)) return;

            var status = root.GetProperty("status").GetString() ?? "online";
            if (status == "offline")
            {
                _db.MarkNodeOffline(nodeId);
                return;
            }

            var ip = root.TryGetProperty("ip", out var ipEl) && !string.IsNullOrWhiteSpace(ipEl.GetString())
                ? ipEl.GetString()!
                : remoteIp;
            var port = root.GetProperty("httpPort").GetInt32();
            var announcedThumb = root.GetProperty("certificateThumbprintSha256").GetString() ?? "";

            await ProbeAndUpsertNodeAsync(ip, port, "beacon", announcedThumb);
        }
        catch { }
    }

    public async Task<DirectoryNodeRecord> RegisterManualNodeAsync(string ip, int port)
    {
        var rec = await ProbeAndUpsertNodeAsync(ip.Trim(), port, "manual", expectedThumb: null)
            ?? throw new ProtocolException("E-INTERNAL", 502, "Nodo inaccesible", $"No se pudo verificar el nodo en {ip}:{port}.");
        return rec;
    }

    public async Task<List<DirectoryNodeRecord>> ScanSubnetAsync(CancellationToken ct = default)
    {
        var localIp = GetLocalLanIp();
        var found = new List<DirectoryNodeRecord>();
        var parts = localIp.Split('.');
        if (parts.Length != 4) return found;

        var prefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";
        using var sem = new SemaphoreSlim(64);
        var tasks = new List<Task>();
        var lockObj = new object();

        // Incluye 127.0.0.1 para pruebas locales multi-nodo + subred /24
        var hosts = Enumerable.Range(1, 254).Select(i => prefix + i).Append("127.0.0.1").Distinct().ToList();

        foreach (var host in hosts)
        {
            for (var port = 5001; port <= 5020; port++)
            {
                if (host == localIp && port == SqliteDatabaseService.LocalHttpPort) continue;
                if (host == "127.0.0.1" && port == SqliteDatabaseService.LocalHttpPort) continue;

                var h = host;
                var p = port;
                tasks.Add(Task.Run(async () =>
                {
                    await sem.WaitAsync(ct);
                    try
                    {
                        var rec = await ProbeAndUpsertNodeAsync(h, p, "scan", expectedThumb: null, timeoutMs: 500);
                        if (rec is not null)
                        {
                            lock (lockObj) found.Add(rec);
                        }
                    }
                    catch { }
                    finally { sem.Release(); }
                }, ct));
            }
        }

        await Task.WhenAll(tasks);
        return found;
    }

    public async Task<DirectoryNodeRecord?> ProbeAndUpsertNodeAsync(string ip, int port, string source, string? expectedThumb, int timeoutMs = 4000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        using var client = _httpFactory.CreateClient("NodeDiscovery");
        var baseUrl = $"http://{ip}:{port}";

        using var statusReq = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/status");
        AddProtocolHeaders(statusReq);
        using var statusResp = await client.SendAsync(statusReq, cts.Token);
        if (!statusResp.IsSuccessStatusCode) return null;

        var statusJson = await statusResp.Content.ReadAsStringAsync(cts.Token);
        using var statusDoc = JsonDocument.Parse(statusJson);
        var root = statusDoc.RootElement;

        if (!root.TryGetProperty("protocolVersion", out var verEl) || verEl.GetString() != "2.0") return null;
        var nodeId = root.GetProperty("nodeId").GetString() ?? "";
        if (string.Equals(nodeId, SqliteDatabaseService.LocalNodeId, StringComparison.Ordinal)) return null;

        var teamNum = root.GetProperty("teamNumber").GetInt32();
        var httpPort = root.TryGetProperty("httpPort", out var hpEl) ? hpEl.GetInt32() : port;
        int? httpsPort = root.TryGetProperty("httpsPort", out var hspEl) && hspEl.ValueKind == JsonValueKind.Number ? hspEl.GetInt32() : null;
        var statusThumb = root.GetProperty("certificateThumbprintSha256").GetString() ?? "";

        var algos = new List<string>();
        if (root.TryGetProperty("algorithms", out var algosEl) && algosEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in algosEl.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String) algos.Add(item.GetString()!);
                else if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("algorithmCode", out var c))
                    algos.Add(c.GetString()!);
            }
        }

        using var certReq = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/certificate");
        AddProtocolHeaders(certReq);
        using var certResp = await client.SendAsync(certReq, cts.Token);
        if (!certResp.IsSuccessStatusCode) return null;
        var certPem = await certResp.Content.ReadAsStringAsync(cts.Token);

        // Validar CN == nodeId y huella == statusThumb (Sección 6.3)
        using var cert = X509Certificate2.CreateFromPem(certPem);
        var cn = CertificateAndZipService.ExtractCommonName(cert);
        if (!string.Equals(cn, nodeId, StringComparison.Ordinal)) return null;

        var actualThumb = CertificateAndZipService.ComputeThumbprintSha256Upper(certPem);
        if (!CertificateAndZipService.FixedTimeEqualsAscii(actualThumb, statusThumb)) return null;
        if (!string.IsNullOrEmpty(expectedThumb) && !CertificateAndZipService.FixedTimeEqualsAscii(actualThumb, expectedThumb)) return null;

        var record = new DirectoryNodeRecord
        {
            NodeId = nodeId,
            TeamNumber = teamNum,
            Ip = ip,
            HttpPort = httpPort,
            HttpsPort = httpsPort,
            CertificatePem = certPem,
            AnnouncedThumbprintSha256 = actualThumb,
            Algorithms = algos,
            Source = source,
            Status = "online",
            LastSeenUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        return _db.UpsertDirectoryNode(record);
    }

    public static void AddProtocolHeaders(HttpRequestMessage msg, string? requestId = null)
    {
        msg.Headers.TryAddWithoutValidation("X-CC-Node", SqliteDatabaseService.LocalNodeId);
        msg.Headers.TryAddWithoutValidation("X-CC-Protocol", "2.0");
        msg.Headers.TryAddWithoutValidation("X-CC-Request-Id", requestId ?? Guid.NewGuid().ToString("D").ToLowerInvariant());
    }
}
