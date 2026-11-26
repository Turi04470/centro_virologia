using System.Globalization;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Crypto;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Network;
using CentroCiberseguridad.Web.Services.Transfer;

var builder = WebApplication.CreateBuilder(args);

var dbPath = builder.Configuration["DatabasePath"] ?? Path.Combine(builder.Environment.ContentRootPath, "ciberseguridad.db");
builder.Services.AddSingleton(_ => new SqliteDatabaseService(dbPath));
builder.Services.AddSingleton<CertificateAndZipService>();
builder.Services.AddSingleton<CryptoEngineService>();
builder.Services.AddSingleton<RemoteCryptoClient>();
builder.Services.AddSingleton<DiscoveryAndDirectoryService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DiscoveryAndDirectoryService>());

builder.Services.AddHttpClient("NodeTransfer", client => client.Timeout = TimeSpan.FromSeconds(40));
builder.Services.AddHttpClient("NodeDiscovery", client => client.Timeout = TimeSpan.FromSeconds(5));
builder.Services.AddCors(opts => opts.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var app = builder.Build();
var cryptoConcurrency = new SemaphoreSlim(10, 10);

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// Inicializa base de datos y certificado local EQ04 al arrancar
app.Services.GetRequiredService<CertificateAndZipService>().GetLocalCertificate();

static IResult ProblemError(string code, int status, string title, string detail, string? requestId = null)
{
    var body = new
    {
        type = $"https://centrociber.local/errors/{code}",
        title,
        status,
        code,
        detail,
        nodeId = SqliteDatabaseService.LocalNodeId,
        requestId,
        timestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    };
    return Results.Json(body, contentType: "application/problem+json", statusCode: status);
}

// ============================================================================
// 1. ESTÁNDAR v2.0 — IDENTIDAD, ESTADO, PERFIL Y LLAVES
// ============================================================================

app.MapGet("/api/status", (CertificateAndZipService certSvc, SqliteDatabaseService db) =>
{
    var cert = certSvc.GetLocalCertificate();
    var owned = db.GetAlgorithms()
        .Where(a => SqliteDatabaseService.OwnedAlgorithmCodes.Contains(a.Code))
        .Select(a => new { algorithmId = a.AlgorithmId, algorithmCode = a.Code })
        .ToArray();

    return Results.Ok(new
    {
        nodeId = SqliteDatabaseService.LocalNodeId,
        teamNumber = SqliteDatabaseService.LocalTeamNumber,
        protocolVersion = "2.0",
        status = "online",
        acceptingPackages = true,
        httpPort = SqliteDatabaseService.LocalHttpPort,
        httpsPort = (int?)null,
        algorithms = owned,
        certificateThumbprintSha256 = cert.ThumbprintSha256,
        serverTimeUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    });
});

app.MapGet("/api/certificate", (CertificateAndZipService certSvc) =>
{
    var pem = certSvc.GetLocalCertificate().CertificatePem;
    return Results.Text(pem, "application/x-pem-file", Encoding.UTF8);
});

app.MapGet("/api/algorithms", () =>
{
    return Results.Ok(new
    {
        nodeId = SqliteDatabaseService.LocalNodeId,
        algorithms = new object[]
        {
            new
            {
                algorithmId = 7,
                algorithmCode = "DIFFIEHELLMAN",
                variants = new[] { "DH-MODP256+A256GCM" },
                operations = new
                {
                    forward = new { name = "cifrar", inputs = new[] { "payload" } },
                    inverse = new { name = "descifrar", inputs = new[] { "package" } }
                },
                secretParameters = Array.Empty<object>(),
                options = new object[]
                {
                    new { name = "allowedNodes", type = "string", required = false }
                },
                publicParameters = new[] { "keyId", "pBase64", "g", "publicValueBase64", "kdf", "nonceBase64", "tagBase64" },
                payloadModes = new[] { "text", "file", "image" },
                maxPayloadBytes = CertificateAndZipService.MaxPackageBytes
            },
            new
            {
                algorithmId = 8,
                algorithmCode = "CAESAR",
                variants = new[] { "A-Z", "BYTE" },
                operations = new
                {
                    forward = new { name = "cifrar", inputs = new[] { "payload" } },
                    inverse = new { name = "descifrar", inputs = new[] { "package" } }
                },
                secretParameters = new object[]
                {
                    new { name = "shift", type = "integer", requiredFor = new[] { "forward", "inverse" } }
                },
                options = new object[]
                {
                    new { name = "alphabet", type = "enum", values = new[] { "A-Z", "BYTE" }, @default = "A-Z" }
                },
                publicParameters = new[] { "alphabet" },
                payloadModes = new[] { "text", "file", "image" },
                maxPayloadBytes = CertificateAndZipService.MaxPackageBytes
            }
        }
    });
});

app.MapGet("/api/keys/{keyId}", (string keyId, SqliteDatabaseService db) =>
{
    var rec = db.GetAsymmetricKey(keyId);
    if (rec is null)
        return ProblemError("E-KEY-NOT-FOUND", 404, "Llave no encontrada", $"keyId '{keyId}' desconocido.");

    return Results.Ok(new
    {
        keyId = rec.KeyId,
        algorithmCode = rec.AlgorithmCode,
        ownerNode = rec.OwnerNode,
        publicParameters = JsonSerializer.Deserialize<Dictionary<string, string>>(rec.PublicParamsJson),
        createdAtUtc = rec.CreatedAtUtc
    });
});

// ============================================================================
// 2. ESTÁNDAR v2.0 — RECEPCIÓN DE PAQUETES Y PROVEEDOR REMOTO (/api/crypto/*)
// ============================================================================

app.MapPost("/api/requests/receive", async (
    HttpRequest request,
    SqliteDatabaseService db,
    CertificateAndZipService certZip) =>
{
    var reqIdHeader = request.Headers["X-CC-Request-Id"].FirstOrDefault();
    if (!request.HasFormContentType)
        return ProblemError("E-UNSUPPORTED-MEDIA", 415, "Tipo no soportado", "Se requiere multipart/form-data con campo 'package'.", reqIdHeader);

    var form = await request.ReadFormAsync();
    var file = form.Files["package"] ?? form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
        return ProblemError("E-ZIP-INVALID", 400, "Paquete faltante", "No se recibió el archivo 'package'.", reqIdHeader);

    if (file.Length > CertificateAndZipService.MaxPackageBytes)
        return ProblemError("E-SIZE", 413, "Paquete demasiado grande", "El paquete ZIP supera el límite de 50 MB.", reqIdHeader);

    byte[] zipBytes;
    using (var ms = new MemoryStream())
    {
        await file.CopyToAsync(ms);
        zipBytes = ms.ToArray();
    }

    var val = certZip.ValidateZipPackage(zipBytes, checkReplay: true, checkTimestamp: true, checkDirectoryTrust: true);
    if (!val.IsValid || val.Manifest is null)
        return ProblemError(val.ErrorCode, val.HttpStatusCode, "Validación de paquete fallida", val.ErrorMessage, reqIdHeader);

    var mf = val.Manifest;
    var remoteIp = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? mf.SourceIp;
    var zipName = string.IsNullOrWhiteSpace(file.FileName)
        ? CertificateAndZipService.BuildStandardZipName(mf.PacketType, mf.SourceNode, mf.AlgorithmCode, mf.TimestampUtc, mf.EncryptedSha256)
        : Path.GetFileName(file.FileName);

    var receivedAtUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    var id = db.AddIncomingRequest(new IncomingRequestRecord
    {
        PacketId = mf.PacketId,
        SourceNode = mf.SourceNode,
        SourceIp = remoteIp,
        ZipFileName = zipName,
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.AlgorithmName,
        OperationName = mf.OperationName,
        SignatureValid = true,
        TrustStatus = val.TrustStatus,
        Status = "Pendiente",
        EncryptedSha256 = mf.EncryptedSha256,
        ReceivedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
        ZipBytes = zipBytes
    });

    return Results.Accepted($"/api/requests/{id}", new
    {
        packetId = mf.PacketId,
        status = "Pendiente",
        receivedAtUtc
    });
}).DisableAntiforgery();

app.MapPost("/api/crypto/forward", async (
    HttpRequest request,
    SqliteDatabaseService db,
    CertificateAndZipService certZip,
    CryptoEngineService crypto) =>
{
    return await HandleProviderOperationAsync(request, isForward: true, db, certZip, crypto, cryptoConcurrency);
}).DisableAntiforgery();

app.MapPost("/api/crypto/inverse", async (
    HttpRequest request,
    SqliteDatabaseService db,
    CertificateAndZipService certZip,
    CryptoEngineService crypto) =>
{
    return await HandleProviderOperationAsync(request, isForward: false, db, certZip, crypto, cryptoConcurrency);
}).DisableAntiforgery();

app.MapGet("/api/jobs/{jobId}", (string jobId, SqliteDatabaseService db) =>
{
    var job = db.GetAsyncJob(jobId);
    if (job is null) return ProblemError("E-JOB-NOT-FOUND", 404, "Trabajo no encontrado", $"jobId '{jobId}' no existe o expiró.");

    return Results.Ok(new
    {
        jobId = job.JobId,
        state = job.State,
        progressPercent = job.ProgressPercent,
        resultUrl = job.State == "done" ? $"/api/jobs/{job.JobId}/result" : null,
        error = job.ErrorJson is null ? null : JsonSerializer.Deserialize<object>(job.ErrorJson)
    });
});

app.MapGet("/api/jobs/{jobId}/result", (string jobId, HttpRequest request, SqliteDatabaseService db) =>
{
    var job = db.GetAsyncJob(jobId);
    if (job is null || job.ResultZipBytes is null)
        return ProblemError("E-JOB-NOT-FOUND", 404, "Resultado no encontrado", $"jobId '{jobId}' no disponible.");

    var callerNode = request.Headers["X-CC-Node"].FirstOrDefault();
    if (!string.Equals(callerNode, job.RequesterNode, StringComparison.Ordinal))
        return ProblemError("E-CERT-UNTRUSTED", 403, "Acceso denegado", "Solo el solicitante original puede descargar este resultado.");

    return Results.File(job.ResultZipBytes, "application/zip", job.ResultFileName ?? "resultado.zip");
});

// ============================================================================
// 3. DIRECTORIO DE NODOS Y DESCUBRIMIENTO (SECCIÓN 6)
// ============================================================================

app.MapGet("/api/nodes", (SqliteDatabaseService db) =>
    Results.Ok(db.GetDirectoryNodes()));

app.MapPost("/api/nodes/scan", async (DiscoveryAndDirectoryService discovery, CancellationToken ct) =>
{
    var found = await discovery.ScanSubnetAsync(ct);
    return Results.Ok(new { foundCount = found.Count, nodes = found });
});

app.MapPost("/api/nodes/manual", async (ManualNodeRequest body, DiscoveryAndDirectoryService discovery) =>
{
    if (string.IsNullOrWhiteSpace(body.Ip) || body.Port <= 0 || body.Port > 65535)
        return ProblemError("E-PARAMS", 400, "Datos inválidos", "Ingresa una IP y puerto válidos.");
    try
    {
        var node = await discovery.RegisterManualNodeAsync(body.Ip, body.Port);
        return Results.Ok(node);
    }
    catch (ProtocolException ex)
    {
        return ProblemError(ex.ErrorCode, ex.HttpStatusCode, ex.Title, ex.Message);
    }
    catch (Exception ex)
    {
        return ProblemError("E-INTERNAL", 502, "Nodo inaccesible", ex.Message);
    }
});

app.MapPost("/api/nodes/{nodeId}/confirm", (string nodeId, SqliteDatabaseService db) =>
{
    var node = db.ConfirmNodeTrust(nodeId);
    return node is null
        ? ProblemError("E-PARAMS", 404, "Nodo no encontrado", $"El nodo '{nodeId}' no existe en el directorio.")
        : Results.Ok(node);
});

app.MapDelete("/api/nodes/{nodeId}", (string nodeId, SqliteDatabaseService db) =>
    db.DeleteDirectoryNode(nodeId)
        ? Results.Ok(new { deleted = true })
        : ProblemError("E-PARAMS", 404, "Nodo no encontrado", $"El nodo '{nodeId}' no existe."));

// ============================================================================
// 4. ENDPOINTS DE LA INTERFAZ LOCAL (AJUSTES, OPERAR, CONSULTAS, SOLICITUDES)
// ============================================================================

app.MapGet("/api/config/algorithms", (SqliteDatabaseService db) =>
    Results.Ok(db.GetAlgorithms()));

app.MapPut("/api/config/algorithms/{code}", (string code, UpdateAlgorithmRequest body, SqliteDatabaseService db) =>
{
    var updated = db.UpdateAlgorithm(code, body.IsVisible, body.CanEncrypt, body.CanDecrypt);
    return updated is null ? Results.NotFound(new { error = "Algoritmo no encontrado." }) : Results.Ok(updated);
});

app.MapPost("/api/config/algorithms/hide-all", (SqliteDatabaseService db) =>
{
    db.HideAllAlgorithms();
    return Results.Ok(db.GetAlgorithms());
});

app.MapGet("/api/config/advanced-mode", (SqliteDatabaseService db) =>
    Results.Ok(new { advancedMode = db.GetAdvancedMode() }));

app.MapPut("/api/config/advanced-mode", (AdvancedModeRequest body, SqliteDatabaseService db) =>
    Results.Ok(new { advancedMode = db.SetAdvancedMode(body.Enabled) }));

app.MapPost("/api/crypto/operate", async (
    OperateRequest req,
    SqliteDatabaseService db,
    CryptoEngineService crypto,
    RemoteCryptoClient remoteClient) =>
{
    try
    {
        var algo = db.GetAlgorithm(req.AlgorithmCode);
        if (algo is not null)
        {
            var provider = remoteClient.FindOnlineTrustedProvider(algo);
            if (provider is not null)
            {
                if (req.IsEncrypt)
                {
                    var delegated = await remoteClient.DelegateForwardAsync(provider, algo, req);
                    return Results.Ok(delegated);
                }
                else if (req.SourceConsultaId.HasValue)
                {
                    var savedPkg = db.GetSavedPackageById(req.SourceConsultaId.Value);
                    if (savedPkg is not null)
                    {
                        var delegated = await remoteClient.DelegateInverseAsync(provider, algo, savedPkg, req.Key);
                        return Results.Ok(delegated);
                    }
                }
            }

            if (!SqliteDatabaseService.OwnedAlgorithmCodes.Contains(algo.Code) && !db.GetAdvancedMode())
            {
                return ProblemError(
                    "E-ALGORITHM-NOT-PROVIDED",
                    403,
                    "Dueño fuera de línea",
                    $"'{algo.Name}' requiere al nodo {algo.OwnerNode ?? "proveedor"} en línea o activar Modo avanzado en Ajustes.");
            }
        }

        var result = crypto.Execute(req);
        return Results.Ok(result);
    }
    catch (ProtocolException ex)
    {
        return ProblemError(ex.ErrorCode, ex.HttpStatusCode, ex.Title, ex.Message);
    }
    catch (UnauthorizedAccessException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status403Forbidden);
    }
    catch (CryptographicException ex)
    {
        return Results.BadRequest(new { error = $"Error criptográfico: {ex.Message}" });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/consultas", (SqliteDatabaseService db) =>
    Results.Ok(db.GetSavedPackages()));

app.MapGet("/api/consultas/export-all", (SqliteDatabaseService db) =>
{
    var items = db.GetAllSavedPackagesWithBytes();
    if (items.Count == 0)
        return Results.BadRequest(new { error = "No hay registros en Consultas para exportar." });

    using var ms = new MemoryStream();
    var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
    {
        foreach (var item in items)
        {
            var entryName = item.ZipFileName;
            if (!usedNames.Add(entryName))
                entryName = $"{Path.GetFileNameWithoutExtension(item.ZipFileName)}_{item.Id}.zip";
            var entry = archive.CreateEntry(entryName, CompressionLevel.NoCompression);
            using var es = entry.Open();
            es.Write(item.ZipBytes, 0, item.ZipBytes.Length);
        }
    }

    var fileName = $"Consultas_Export_{DateTime.UtcNow:yyyyMMdd_HHmmss}.zip";
    return Results.File(ms.ToArray(), "application/zip", fileName);
});

app.MapDelete("/api/consultas/{id:long}", (long id, SqliteDatabaseService db) =>
    db.DeleteSavedPackage(id)
        ? Results.Ok(new { deleted = true })
        : Results.NotFound(new { error = "Registro no encontrado." }));

app.MapDelete("/api/consultas", (SqliteDatabaseService db) =>
    Results.Ok(new { cleared = db.ClearSavedPackages() }));

app.MapGet("/api/consultas/{id:long}/zip", (long id, SqliteDatabaseService db) =>
{
    var rec = db.GetSavedPackageById(id);
    if (rec is null) return Results.NotFound(new { error = "Registro no encontrado." });
    return Results.File(rec.ZipBytes, "application/zip", rec.ZipFileName);
});

app.MapGet("/api/consultas/{id:long}/unpack", (long id, SqliteDatabaseService db, CertificateAndZipService certZip) =>
{
    var rec = db.GetSavedPackageById(id);
    if (rec is null) return Results.NotFound(new { error = "Registro no encontrado." });

    var val = certZip.ValidateZipPackage(rec.ZipBytes, checkReplay: false, checkTimestamp: false, checkDirectoryTrust: false);
    if (!val.IsValid || val.Manifest is null)
        return ProblemError(val.ErrorCode, val.HttpStatusCode, "Paquete inválido", val.ErrorMessage);

    var mf = val.Manifest;
    var isFileMode = string.Equals(mf.PayloadMode, "file", StringComparison.OrdinalIgnoreCase);
    var isTextNative = mf.AlgorithmCode is "CAESAR" or "VIGENERE" or "HASHSHA" or "HMACSHA256" or "DIGITALSIG" or "DFTSPECTRAL" or "LAGRANGESHAMIR";
    var dataText = isFileMode
        ? string.Empty
        : (isTextNative ? Encoding.UTF8.GetString(val.PayloadBytes) : Convert.ToBase64String(val.PayloadBytes));

    return Results.Ok(new UnpackedPackageResponse
    {
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.AlgorithmName,
        PayloadMode = isFileMode ? "file" : "text",
        OriginalFileName = mf.OriginalFileName,
        DataText = dataText,
        DataBase64 = Convert.ToBase64String(val.PayloadBytes),
        EncryptedSha256 = mf.EncryptedSha256,
        SignatureValid = true,
        KeyId = mf.KeyRef?.KeyId,
        Manifest = mf
    });
});

app.MapPost("/api/consultas/{id:long}/send", async (
    long id,
    SendZipRequest body,
    SqliteDatabaseService db,
    CertificateAndZipService certZip,
    IHttpClientFactory httpFactory) =>
{
    var rec = db.GetSavedPackageById(id);
    if (rec is null) return Results.NotFound(new { error = "Registro no encontrado." });

    string rawTarget;
    if (!string.IsNullOrWhiteSpace(body.TargetNodeId))
    {
        var node = db.GetDirectoryNode(body.TargetNodeId);
        if (node is null) return Results.BadRequest(new { error = $"Nodo '{body.TargetNodeId}' no encontrado." });
        rawTarget = $"{node.Ip}:{node.HttpPort}";
    }
    else if (!string.IsNullOrWhiteSpace(body.TargetIp))
    {
        rawTarget = body.TargetIp.Trim().TrimEnd('/');
    }
    else
    {
        return Results.BadRequest(new { error = "Se requiere TargetIp o TargetNodeId." });
    }

    var url = rawTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
              rawTarget.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        ? (rawTarget.Contains("/api/", StringComparison.OrdinalIgnoreCase) ? rawTarget : $"{rawTarget}/api/requests/receive")
        : $"http://{rawTarget}/api/requests/receive";

    // Sección 9.6: Reempaquetar con nuevo packetId, timestampUtc y firma de EQ04 conservando producerNode
    var localIpPort = $"{DiscoveryAndDirectoryService.GetLocalLanIp()}:{SqliteDatabaseService.LocalHttpPort}";
    var (repackedZip, repackedName, repackedMf) = certZip.RepackageForForwarding(rec.ZipBytes, localIpPort);

    try
    {
        using var client = httpFactory.CreateClient("NodeTransfer");
        using var form = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(repackedZip);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        form.Add(fileContent, "package", repackedName);

        using var reqMsg = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
        DiscoveryAndDirectoryService.AddProtocolHeaders(reqMsg, repackedMf.PacketId);

        using var resp = await client.SendAsync(reqMsg);
        var respBody = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
        {
            return Results.Json(
                new { error = $"El nodo remoto ({url}) respondió HTTP {(int)resp.StatusCode}: {respBody}" },
                statusCode: StatusCodes.Status502BadGateway);
        }

        return Results.Ok(new { sent = true, targetUrl = url, fileName = repackedName, remoteStatus = (int)resp.StatusCode });
    }
    catch (Exception ex)
    {
        return Results.Json(
            new { error = $"No se pudo conectar con {url}: {ex.Message}" },
            statusCode: StatusCodes.Status502BadGateway);
    }
});

app.MapPost("/api/requests/simulate", (SqliteDatabaseService db, CertificateAndZipService certZip) =>
{
    var samplePlain = Encoding.UTF8.GetBytes($"Mensaje de prueba v2.0 · {DateTime.UtcNow:HH:mm:ss}");
    var algo = db.GetAlgorithm("CAESAR")!;
    var shifted = samplePlain.Select(b => (byte)((b + 3) % 256)).ToArray();

    var (zipBytes, zipName, mf) = certZip.CreateSignedZipPackage(
        shifted,
        algo,
        packetType: "package",
        operation: "forward",
        payloadMode: "text",
        originalFileName: "prueba_v2.txt",
        originalSizeBytes: samplePlain.Length,
        contentType: "text/plain",
        sourceIp: $"{DiscoveryAndDirectoryService.GetLocalLanIp()}:{SqliteDatabaseService.LocalHttpPort}",
        publicParams: new Dictionary<string, string> { ["alphabet"] = "BYTE" });

    var reqId = db.AddIncomingRequest(new IncomingRequestRecord
    {
        PacketId = mf.PacketId,
        SourceNode = mf.SourceNode,
        SourceIp = mf.SourceIp,
        ZipFileName = zipName,
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.AlgorithmName,
        OperationName = mf.OperationName,
        SignatureValid = true,
        TrustStatus = "Firma OK",
        Status = "Pendiente",
        EncryptedSha256 = mf.EncryptedSha256,
        ReceivedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
        ZipBytes = zipBytes
    });

    return Results.Ok(new { id = reqId, zipFileName = zipName });
});

app.MapGet("/api/requests", (SqliteDatabaseService db) =>
    Results.Ok(db.GetIncomingRequests()));

app.MapPost("/api/requests/{id:long}/accept", (long id, SqliteDatabaseService db) =>
{
    var saved = db.AcceptIncomingRequest(id);
    return saved is null
        ? Results.BadRequest(new { error = "La solicitud no existe o ya fue procesada." })
        : Results.Ok(saved);
});

app.MapPost("/api/requests/{id:long}/reject", (long id, SqliteDatabaseService db) =>
    db.RejectIncomingRequest(id)
        ? Results.Ok(new { rejected = true })
        : Results.BadRequest(new { error = "La solicitud no existe o ya fue procesada." }));

app.Run();

static async Task<IResult> HandleProviderOperationAsync(
    HttpRequest request,
    bool isForward,
    SqliteDatabaseService db,
    CertificateAndZipService certZip,
    CryptoEngineService crypto,
    SemaphoreSlim concurrency)
{
    var reqIdHeader = request.Headers["X-CC-Request-Id"].FirstOrDefault();
    if (!await concurrency.WaitAsync(0))
        return ProblemError("E-BUSY", 503, "Nodo ocupado", "Se superó el límite de 10 peticiones simultáneas.", reqIdHeader);

    try
    {
        if (!request.HasFormContentType)
            return ProblemError("E-UNSUPPORTED-MEDIA", 415, "Tipo no soportado", "Se requiere multipart/form-data.", reqIdHeader);

        var form = await request.ReadFormAsync();
        byte[]? requestBytes = null;
        if (form.Files["request"] is IFormFile reqFile)
        {
            using var ms = new MemoryStream();
            await reqFile.CopyToAsync(ms);
            requestBytes = ms.ToArray();
        }
        else if (form.TryGetValue("request", out var reqStr))
        {
            requestBytes = Encoding.UTF8.GetBytes(reqStr.ToString());
        }

        var reqSigBase64 = form["requestSignature"].FirstOrDefault();
        string? requesterCertPem = form["requesterCertificate"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(requesterCertPem) && form.Files["requesterCertificate"] is IFormFile certFile)
        {
            using var sr = new StreamReader(certFile.OpenReadStream(), Encoding.UTF8);
            requesterCertPem = await sr.ReadToEndAsync();
        }

        if (requestBytes is null || string.IsNullOrWhiteSpace(reqSigBase64) || string.IsNullOrWhiteSpace(requesterCertPem))
            return ProblemError("E-REQUEST", 400, "Petición incompleta", "Faltan partes obligatorias (request, requestSignature, requesterCertificate).", reqIdHeader);

        CryptoRemoteRequestDto? remoteReq;
        try
        {
            remoteReq = JsonSerializer.Deserialize<CryptoRemoteRequestDto>(requestBytes, CertificateAndZipService.JsonOpts);
        }
        catch
        {
            return ProblemError("E-REQUEST", 400, "JSON inválido", "La parte 'request' no es JSON válido.", reqIdHeader);
        }

        if (remoteReq is null || string.IsNullOrWhiteSpace(remoteReq.RequestId) || string.IsNullOrWhiteSpace(remoteReq.RequesterNode))
            return ProblemError("E-REQUEST", 400, "Petición inválida", "Faltan campos obligatorios en 'request'.", reqIdHeader);

        if (remoteReq.Version != "2.0")
            return ProblemError("E-VERSION", 400, "Versión no soportada", $"Versión '{remoteReq.Version}' no soportada.", remoteReq.RequestId);

        if (!string.Equals(remoteReq.TargetNode, SqliteDatabaseService.LocalNodeId, StringComparison.Ordinal))
            return ProblemError("E-REQUEST", 400, "Destinatario incorrecto", $"targetNode debe ser '{SqliteDatabaseService.LocalNodeId}'.", remoteReq.RequestId);

        // Validar certificado del solicitante
        using var reqCert = X509Certificate2.CreateFromPem(requesterCertPem);
        var cn = CertificateAndZipService.ExtractCommonName(reqCert);
        if (!string.Equals(cn, remoteReq.RequesterNode, StringComparison.Ordinal))
            return ProblemError("E-CERT", 422, "Certificado inválido", $"CN '{cn}' no coincide con requesterNode '{remoteReq.RequesterNode}'.", remoteReq.RequestId);

        var dirNode = db.GetDirectoryNode(remoteReq.RequesterNode);
        var reqThumb = CertificateAndZipService.ComputeThumbprintSha256Upper(requesterCertPem);
        if (dirNode is not null && !string.IsNullOrEmpty(dirNode.PinnedThumbprintSha256) &&
            !CertificateAndZipService.FixedTimeEqualsAscii(dirNode.PinnedThumbprintSha256, reqThumb))
            return ProblemError("E-CERT-UNTRUSTED", 403, "Certificado no confiable", "La huella del solicitante difiere de la fijada.", remoteReq.RequestId);

        // Validar firma sobre los bytes exactos de request
        byte[] reqSigBytes;
        try { reqSigBytes = Convert.FromBase64String(reqSigBase64); }
        catch { return ProblemError("E-REQUEST-SIGNATURE", 401, "Firma inválida", "requestSignature no es Base64 válido.", remoteReq.RequestId); }

        if (!CertificateAndZipService.VerifyWithPem(requestBytes, reqSigBytes, requesterCertPem))
            return ProblemError("E-REQUEST-SIGNATURE", 401, "Firma inválida", "La firma RSA-PSS-SHA256 de 'request' no es válida.", remoteReq.RequestId);

        // Ventana de tiempo +-10 min y replay protection
        if (!DateTime.TryParseExact(remoteReq.TimestampUtc, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts) ||
            Math.Abs((DateTime.UtcNow - ts).TotalMinutes) > CertificateAndZipService.TimestampWindow.TotalMinutes)
            return ProblemError("E-TIMESTAMP", 422, "Timestamp fuera de ventana", "timestampUtc excede ±10 min.", remoteReq.RequestId);

        if (!db.TryRegisterSeenId(remoteReq.RequestId, "request"))
            return ProblemError("E-DUPLICATE", 409, "Petición duplicada", $"requestId '{remoteReq.RequestId}' ya fue procesado.", remoteReq.RequestId);

        // Abrir sobre CC-ENV-1 si trae secretos
        Dictionary<string, string>? secrets = null;
        if (remoteReq.Secrets is not null)
        {
            var secretPlain = certZip.UnwrapEnvelope(remoteReq.Secrets, null, remoteReq.RequestId);
            secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(secretPlain, CertificateAndZipService.JsonOpts);
            CryptographicOperations.ZeroMemory(secretPlain);
        }

        var localIpPort = $"{DiscoveryAndDirectoryService.GetLocalLanIp()}:{SqliteDatabaseService.LocalHttpPort}";

        if (isForward)
        {
            var payloadFile = form.Files["payload"];
            if (payloadFile is null)
                return ProblemError("E-REQUEST", 400, "Payload faltante", "Se requiere la parte 'payload' en forward.", remoteReq.RequestId);
            if (payloadFile.Length > CertificateAndZipService.MaxPackageBytes)
                return ProblemError("E-SIZE", 413, "Payload excedido", "Máximo 50 MB.", remoteReq.RequestId);

            byte[] payloadBytes;
            using (var ms = new MemoryStream()) { await payloadFile.CopyToAsync(ms); payloadBytes = ms.ToArray(); }

            var (zipBytes, zipName, _) = crypto.ExecuteProviderForward(remoteReq, payloadBytes, secrets, localIpPort);
            return Results.File(zipBytes, "application/zip", zipName);
        }
        else
        {
            var pkgFile = form.Files["package"];
            if (pkgFile is null)
                return ProblemError("E-REQUEST", 400, "Paquete faltante", "Se requiere la parte 'package' en inverse.", remoteReq.RequestId);
            if (pkgFile.Length > CertificateAndZipService.MaxPackageBytes)
                return ProblemError("E-SIZE", 413, "Paquete excedido", "Máximo 50 MB.", remoteReq.RequestId);

            byte[] pkgBytes;
            using (var ms = new MemoryStream()) { await pkgFile.CopyToAsync(ms); pkgBytes = ms.ToArray(); }

            var pkgVal = certZip.ValidateZipPackage(pkgBytes, checkReplay: false, checkTimestamp: false, checkDirectoryTrust: false, expectedPacketType: "package");
            if (!pkgVal.IsValid)
                return ProblemError(pkgVal.ErrorCode, pkgVal.HttpStatusCode, "Paquete inválido", pkgVal.ErrorMessage, remoteReq.RequestId);

            var (resZipBytes, resZipName, _) = crypto.ExecuteProviderInverse(remoteReq, pkgVal, secrets, requesterCertPem, localIpPort);
            return Results.File(resZipBytes, "application/zip", resZipName);
        }
    }
    catch (ProtocolException ex)
    {
        return ProblemError(ex.ErrorCode, ex.HttpStatusCode, ex.Title, ex.Message, reqIdHeader);
    }
    catch (Exception ex)
    {
        return ProblemError("E-INTERNAL", 500, "Error interno", ex.Message, reqIdHeader);
    }
    finally
    {
        concurrency.Release();
    }
}

public partial class Program { }
