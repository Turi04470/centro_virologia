using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Transfer;

namespace CentroCiberseguridad.Web.Services.Network;

public sealed class RemoteCryptoClient
{
    private readonly SqliteDatabaseService _db;
    private readonly CertificateAndZipService _certZip;
    private readonly IHttpClientFactory _httpFactory;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public RemoteCryptoClient(SqliteDatabaseService db, CertificateAndZipService certZip, IHttpClientFactory httpFactory)
    {
        _db = db;
        _certZip = certZip;
        _httpFactory = httpFactory;
    }

    public DirectoryNodeRecord? FindOnlineTrustedProvider(AlgorithmConfig algo)
    {
        if (string.Equals(algo.OwnerNode, SqliteDatabaseService.LocalNodeId, StringComparison.Ordinal))
            return null;

        var nodes = _db.GetDirectoryNodes()
            .Where(n => n.Status == "online" && !n.TrustAlert && !string.IsNullOrEmpty(n.PinnedThumbprintSha256))
            .ToList();

        // Preferir dueño oficial de la tabla 4.1
        if (!string.IsNullOrEmpty(algo.OwnerNode))
        {
            var owner = nodes.FirstOrDefault(n => string.Equals(n.NodeId, algo.OwnerNode, StringComparison.Ordinal));
            if (owner is not null) return owner;
        }

        // Para algoritmos reservados (17-21), gana el teamNumber menor que lo anuncie
        return nodes
            .Where(n => n.Algorithms.Contains(algo.Code, StringComparer.Ordinal))
            .OrderBy(n => n.TeamNumber)
            .FirstOrDefault();
    }

    public async Task<OperateResponse> DelegateForwardAsync(DirectoryNodeRecord provider, AlgorithmConfig algo, OperateRequest req)
    {
        var isFile = string.Equals(req.InputMode, "file", StringComparison.OrdinalIgnoreCase);
        var payloadBytes = isFile
            ? Convert.FromBase64String(req.FileBase64 ?? string.Empty)
            : Encoding.UTF8.GetBytes(req.Text ?? string.Empty);

        var requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        CcEnvelope? secretsEnv = null;

        if (!string.IsNullOrWhiteSpace(req.Key))
        {
            var secretMap = BuildSecretDictionary(algo.Code, req.Key);
            var secretBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(secretMap, JsonOpts));
            (secretsEnv, _) = CertificateAndZipService.WrapEnvelope(secretBytes, provider.NodeId, provider.CertificatePem, requestId, includeCiphertextInJson: true);
        }

        var remoteReq = new CryptoRemoteRequestDto
        {
            Version = "2.0",
            RequestId = requestId,
            RequesterNode = SqliteDatabaseService.LocalNodeId,
            TargetNode = provider.NodeId,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = algo.Code,
            Operation = "forward",
            PayloadMode = isFile ? "file" : "text",
            OriginalFileName = string.IsNullOrWhiteSpace(req.FileName) ? (isFile ? "archivo.bin" : "mensaje.txt") : req.FileName!,
            Options = new Dictionary<string, string>(),
            KeyId = req.KeyId,
            Secrets = secretsEnv
        };

        var reqJsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(remoteReq, JsonOpts));
        var reqSigBase64 = Convert.ToBase64String(_certZip.SignWithLocalKey(reqJsonBytes));
        var localCertPem = _certZip.GetLocalCertificate().CertificatePem;

        using var form = new MultipartFormDataContent();
        var reqPart = new ByteArrayContent(reqJsonBytes);
        reqPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        form.Add(reqPart, "request");
        form.Add(new StringContent(reqSigBase64, Encoding.UTF8), "requestSignature");
        form.Add(new StringContent(localCertPem, Encoding.UTF8), "requesterCertificate");
        var payloadPart = new ByteArrayContent(payloadBytes);
        payloadPart.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(payloadPart, "payload", remoteReq.OriginalFileName);

        var zipBytes = await SendCryptoRequestAndPollAsync(provider, "/api/crypto/forward", form, requestId);
        var val = _certZip.ValidateZipPackage(zipBytes, checkReplay: false, checkTimestamp: true, checkDirectoryTrust: true, expectedPacketType: "package");
        if (!val.IsValid || val.Manifest is null)
            throw new ProtocolException(val.ErrorCode, val.HttpStatusCode, "Respuesta remota inválida", val.ErrorMessage);

        var mf = val.Manifest;
        var zipName = CertificateAndZipService.BuildStandardZipName("package", mf.SourceNode, mf.AlgorithmCode, mf.TimestampUtc, mf.EncryptedSha256);
        var consultaId = _db.AddSavedPackage(new SavedPackageRecord
        {
            ZipFileName = zipName,
            Origin = "Generado",
            SourceNode = mf.SourceNode,
            ProducerNode = mf.ProducerNode,
            SourceIp = $"{provider.Ip}:{provider.HttpPort}",
            PacketType = "package",
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.AlgorithmName,
            EncryptedSha256 = mf.EncryptedSha256,
            CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
            ZipBytes = zipBytes
        });

        var isTextNative = mf.AlgorithmCode is "CAESAR" or "VIGENERE" or "HASHSHA" or "HMACSHA256" or "DIGITALSIG" or "DFTSPECTRAL" or "LAGRANGESHAMIR";
        var outText = isFile
            ? $"[{zipName}] (Delegado a {provider.NodeId})"
            : (isTextNative ? Encoding.UTF8.GetString(val.PayloadBytes) : Convert.ToBase64String(val.PayloadBytes));

        return new OperateResponse
        {
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.AlgorithmName,
            IsEncrypt = true,
            ExecutionMode = $"delegado ({provider.NodeId})",
            ProducerNode = mf.ProducerNode,
            OutputText = outText,
            OutputBase64 = Convert.ToBase64String(val.PayloadBytes),
            OutputFileName = zipName,
            Sha256 = mf.EncryptedSha256,
            ZipFileName = zipName,
            ConsultaId = consultaId,
            Cells = Enumerable.Range(0, 16).Select(i => (val.PayloadBytes.Length > 0 ? val.PayloadBytes[i % val.PayloadBytes.Length] : (byte)0).ToString("X2")).ToArray(),
            Steps = new[]
            {
                $"Delegado vía POST /api/crypto/forward a {provider.NodeId} ({provider.Ip}:{provider.HttpPort})",
                $"Secretos protegidos con sobre CC-ENV-1",
                $"Firma RSA-PSS-SHA256 de {provider.NodeId} verificada OK"
            },
            Manifest = mf
        };
    }

    public async Task<OperateResponse> DelegateInverseAsync(DirectoryNodeRecord provider, AlgorithmConfig algo, SavedPackageRecord savedPkg, string key)
    {
        var requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        CcEnvelope? secretsEnv = null;
        if (!string.IsNullOrWhiteSpace(key))
        {
            var secretMap = BuildSecretDictionary(algo.Code, key);
            var secretBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(secretMap, JsonOpts));
            (secretsEnv, _) = CertificateAndZipService.WrapEnvelope(secretBytes, provider.NodeId, provider.CertificatePem, requestId, includeCiphertextInJson: true);
        }

        var remoteReq = new CryptoRemoteRequestDto
        {
            Version = "2.0",
            RequestId = requestId,
            RequesterNode = SqliteDatabaseService.LocalNodeId,
            TargetNode = provider.NodeId,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = algo.Code,
            Operation = "inverse",
            PayloadMode = "file",
            OriginalFileName = savedPkg.ZipFileName,
            Options = new Dictionary<string, string>(),
            KeyId = null,
            Secrets = secretsEnv
        };

        var reqJsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(remoteReq, JsonOpts));
        var reqSigBase64 = Convert.ToBase64String(_certZip.SignWithLocalKey(reqJsonBytes));
        var localCertPem = _certZip.GetLocalCertificate().CertificatePem;

        using var form = new MultipartFormDataContent();
        var reqPart = new ByteArrayContent(reqJsonBytes);
        reqPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        form.Add(reqPart, "request");
        form.Add(new StringContent(reqSigBase64, Encoding.UTF8), "requestSignature");
        form.Add(new StringContent(localCertPem, Encoding.UTF8), "requesterCertificate");
        var pkgPart = new ByteArrayContent(savedPkg.ZipBytes);
        pkgPart.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        form.Add(pkgPart, "package", savedPkg.ZipFileName);

        var resultZipBytes = await SendCryptoRequestAndPollAsync(provider, "/api/crypto/inverse", form, requestId);
        var val = _certZip.ValidateZipPackage(resultZipBytes, checkReplay: false, checkTimestamp: true, checkDirectoryTrust: true, expectedPacketType: "result");
        if (!val.IsValid || val.Manifest is null || val.Manifest.ResultEnvelope is null)
            throw new ProtocolException(val.ErrorCode, val.HttpStatusCode, "Resultado remoto inválido", val.ErrorMessage);

        var mf = val.Manifest;
        var plainBytes = _certZip.UnwrapEnvelope(mf.ResultEnvelope, val.PayloadBytes, mf.PacketId);
        var plainSha = Convert.ToHexString(SHA256.HashData(plainBytes)).ToLowerInvariant();
        var resZipName = CertificateAndZipService.BuildStandardZipName("result", mf.SourceNode, mf.AlgorithmCode, mf.TimestampUtc, mf.EncryptedSha256);

        var consultaId = _db.AddSavedPackage(new SavedPackageRecord
        {
            ZipFileName = resZipName,
            Origin = "Resultado",
            SourceNode = mf.SourceNode,
            ProducerNode = mf.ProducerNode,
            SourceIp = $"{provider.Ip}:{provider.HttpPort}",
            PacketType = "result",
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.AlgorithmName,
            EncryptedSha256 = mf.EncryptedSha256,
            CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
            ZipBytes = resultZipBytes
        });

        var isFile = mf.PayloadMode != "text";
        return new OperateResponse
        {
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.AlgorithmName,
            IsEncrypt = false,
            ExecutionMode = $"delegado ({provider.NodeId})",
            ProducerNode = mf.ProducerNode,
            OutputText = isFile ? $"[{mf.OriginalFileName}] ({plainBytes.Length} B)" : Encoding.UTF8.GetString(plainBytes),
            OutputBase64 = Convert.ToBase64String(plainBytes),
            OutputFileName = mf.OriginalFileName,
            Sha256 = plainSha,
            ZipFileName = resZipName,
            ConsultaId = consultaId,
            Cells = Enumerable.Range(0, 16).Select(i => (plainBytes.Length > 0 ? plainBytes[i % plainBytes.Length] : (byte)0).ToString("X2")).ToArray(),
            Steps = new[]
            {
                $"Delegado vía POST /api/crypto/inverse a {provider.NodeId}",
                $"Sobre CC-ENV-1 abierto con llave privada local de EQ04",
                mf.Verification is not null ? $"Verificación: {(mf.Verification.Valid ? "OK" : "FALLO")} ({mf.Verification.Detail})" : "Contenido original recuperado"
            },
            Manifest = mf
        };
    }

    private async Task<byte[]> SendCryptoRequestAndPollAsync(DirectoryNodeRecord provider, string path, MultipartFormDataContent form, string requestId)
    {
        using var client = _httpFactory.CreateClient("NodeTransfer");
        var baseUrl = $"http://{provider.Ip}:{provider.HttpPort}";
        using var reqMsg = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}{path}") { Content = form };
        DiscoveryAndDirectoryService.AddProtocolHeaders(reqMsg, requestId);

        using var resp = await client.SendAsync(reqMsg);
        if (resp.StatusCode == System.Net.HttpStatusCode.OK)
            return await resp.Content.ReadAsByteArrayAsync();

        if (resp.StatusCode == System.Net.HttpStatusCode.Accepted)
        {
            var jobJson = await resp.Content.ReadAsStringAsync();
            using var jdoc = JsonDocument.Parse(jobJson);
            var statusUrl = jdoc.RootElement.GetProperty("statusUrl").GetString()!;
            var retrySec = jdoc.RootElement.TryGetProperty("retryAfterSeconds", out var rEl) ? rEl.GetInt32() : 2;

            for (var attempt = 0; attempt < 30; attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(retrySec, 1, 5)));
                using var pollReq = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}{statusUrl}");
                DiscoveryAndDirectoryService.AddProtocolHeaders(pollReq, requestId);
                using var pollResp = await client.SendAsync(pollReq);
                if (!pollResp.IsSuccessStatusCode) continue;

                using var pdoc = JsonDocument.Parse(await pollResp.Content.ReadAsStringAsync());
                var st = pdoc.RootElement.GetProperty("state").GetString();
                if (st == "done")
                {
                    var resUrl = pdoc.RootElement.GetProperty("resultUrl").GetString()!;
                    using var resReq = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}{resUrl}");
                    DiscoveryAndDirectoryService.AddProtocolHeaders(resReq, requestId);
                    using var resResp = await client.SendAsync(resReq);
                    resResp.EnsureSuccessStatusCode();
                    return await resResp.Content.ReadAsByteArrayAsync();
                }
                if (st == "failed")
                    throw new ProtocolException("E-INTERNAL", 502, "Trabajo remoto fallido", "El proveedor reportó fallo en la operación asíncrona.");
            }
            throw new ProtocolException("E-TIMEOUT", 504, "Tiempo agotado", "El trabajo remoto no finalizó a tiempo.");
        }

        var errText = await resp.Content.ReadAsStringAsync();
        throw new ProtocolException("E-INTERNAL", (int)resp.StatusCode, "Error del proveedor remoto", $"{provider.NodeId} respondió HTTP {(int)resp.StatusCode}: {errText}");
    }

    private static Dictionary<string, string> BuildSecretDictionary(string algoCode, string key) => algoCode switch
    {
        "CAESAR" => new Dictionary<string, string> { ["shift"] = key },
        "FISHERYATES" => new Dictionary<string, string> { ["seed"] = key },
        "LSBSTEGO" => new Dictionary<string, string> { ["password"] = key },
        "LORENZSZ40" => new Dictionary<string, string> { ["wheelStarts"] = key },
        _ => new Dictionary<string, string> { ["key"] = key }
    };
}
