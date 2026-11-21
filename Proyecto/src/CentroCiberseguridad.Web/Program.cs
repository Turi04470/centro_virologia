using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Crypto;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Transfer;

var builder = WebApplication.CreateBuilder(args);

var dbPath = builder.Configuration["DatabasePath"] ?? Path.Combine(builder.Environment.ContentRootPath, "ciberseguridad.db");
builder.Services.AddSingleton(_ => new SqliteDatabaseService(dbPath));
builder.Services.AddSingleton<CertificateAndZipService>();
builder.Services.AddSingleton<CryptoEngineService>();
builder.Services.AddHttpClient("NodeTransfer", client =>
{
    client.Timeout = TimeSpan.FromSeconds(15);
});
builder.Services.AddCors(opts =>
{
    opts.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// Inicializa base de datos y certificado local al arrancar
app.Services.GetRequiredService<CertificateAndZipService>().GetLocalCertificate();

app.MapGet("/api/status", (CertificateAndZipService certSvc) =>
{
    var cert = certSvc.GetLocalCertificate();
    return Results.Ok(new
    {
        nodeId = "NODO-04",
        protocolVersion = "1.0",
        status = "online",
        acceptingPackages = true,
        certificateThumbprint = cert.ThumbprintSha256
    });
});

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

app.MapPost("/api/crypto/operate", (OperateRequest req, CryptoEngineService crypto) =>
{
    try
    {
        var result = crypto.Execute(req);
        return Results.Ok(result);
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
{
    return db.DeleteSavedPackage(id)
        ? Results.Ok(new { deleted = true })
        : Results.NotFound(new { error = "Registro no encontrado." });
});

app.MapDelete("/api/consultas", (SqliteDatabaseService db) =>
{
    var removed = db.ClearSavedPackages();
    return Results.Ok(new { cleared = removed });
});

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

    var val = certZip.ValidateZipPackage(rec.ZipBytes);
    if (!val.IsValid || val.Manifest is null)
        return Results.Json(new { error = val.ErrorMessage }, statusCode: val.HttpStatusCode);

    var mf = val.Manifest;
    var isFileMode = string.Equals(mf.PayloadMode, "file", StringComparison.OrdinalIgnoreCase);
    var isTextNative = mf.AlgorithmCode is "CAESAR" or "VIGENERE" or "HASHSHA" or "HMACSHA256" or "DIGITALSIG" or "DFTSPECTRAL" or "LAGRANGESHAMIR";
    var dataText = isFileMode
        ? string.Empty
        : (isTextNative ? Encoding.UTF8.GetString(val.EncryptedBytes) : Convert.ToBase64String(val.EncryptedBytes));

    return Results.Ok(new UnpackedPackageResponse
    {
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.Algorithm,
        PayloadMode = isFileMode ? "file" : "text",
        OriginalFileName = mf.OriginalFileName,
        DataText = dataText,
        DataBase64 = Convert.ToBase64String(val.EncryptedBytes),
        EncryptedSha256 = mf.EncryptedSha256,
        SignatureValid = true
    });
});

app.MapPost("/api/consultas/{id:long}/send", async (
    long id,
    SendZipRequest body,
    SqliteDatabaseService db,
    IHttpClientFactory httpFactory) =>
{
    if (string.IsNullOrWhiteSpace(body.TargetIp))
        return Results.BadRequest(new { error = "Se requiere TargetIp." });

    var rec = db.GetSavedPackageById(id);
    if (rec is null) return Results.NotFound(new { error = "Registro no encontrado." });

    var rawTarget = body.TargetIp.Trim().TrimEnd('/');
    var url = rawTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
              rawTarget.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        ? (rawTarget.Contains("/api/", StringComparison.OrdinalIgnoreCase) ? rawTarget : $"{rawTarget}/api/requests/receive")
        : $"http://{rawTarget}/api/requests/receive";

    try
    {
        using var client = httpFactory.CreateClient("NodeTransfer");
        using var form = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(rec.ZipBytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        form.Add(fileContent, "package", rec.ZipFileName);

        using var reqMsg = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
        reqMsg.Headers.Add("X-Source-Node", "NODO-04");
        reqMsg.Headers.Add("X-Packet-Id", Guid.NewGuid().ToString());

        using var resp = await client.SendAsync(reqMsg);
        var respBody = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
        {
            return Results.Json(
                new { error = $"El nodo remoto ({url}) respondió HTTP {(int)resp.StatusCode}: {respBody}" },
                statusCode: StatusCodes.Status502BadGateway);
        }

        return Results.Ok(new { sent = true, targetUrl = url, fileName = rec.ZipFileName, remoteStatus = (int)resp.StatusCode });
    }
    catch (Exception ex)
    {
        return Results.Json(
            new { error = $"No se pudo conectar con {url}: {ex.Message}" },
            statusCode: StatusCodes.Status502BadGateway);
    }
});

app.MapPost("/api/requests/receive", async (
    HttpRequest request,
    SqliteDatabaseService db,
    CertificateAndZipService certZip) =>
{
    if (!request.HasFormContentType)
        return Results.BadRequest(new { error = "Se requiere multipart/form-data con campo 'package'." });

    var form = await request.ReadFormAsync();
    var file = form.Files["package"] ?? form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "Archivo .zip faltante." });

    const long MaxZipBytes = 50L * 1024 * 1024;
    if (file.Length > MaxZipBytes)
        return Results.Json(new { error = "El paquete ZIP supera el límite de 50 MB." }, statusCode: StatusCodes.Status413PayloadTooLarge);

    byte[] zipBytes;
    using (var ms = new MemoryStream())
    {
        await file.CopyToAsync(ms);
        zipBytes = ms.ToArray();
    }

    var validation = certZip.ValidateZipPackage(zipBytes);
    if (!validation.IsValid || validation.Manifest is null)
        return Results.Json(new { error = validation.ErrorMessage }, statusCode: validation.HttpStatusCode);

    var mf = validation.Manifest;
    var remoteIp = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? mf.SourceIp;
    var zipName = string.IsNullOrWhiteSpace(file.FileName)
        ? CertificateAndZipService.BuildStandardZipName(mf.SourceNode, mf.AlgorithmCode, mf.EncryptedSha256)
        : Path.GetFileName(file.FileName);

    var reqId = db.AddIncomingRequest(new IncomingRequestRecord
    {
        PacketId = mf.PacketId,
        SourceIp = remoteIp,
        ZipFileName = zipName,
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.Algorithm,
        SignatureValid = true,
        Status = "Pendiente",
        EncryptedSha256 = mf.EncryptedSha256,
        ReceivedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
        ZipBytes = zipBytes
    });

    return Results.Accepted($"/api/requests/{reqId}", new
    {
        requestId = reqId,
        status = "Pendiente",
        zipFileName = zipName,
        algorithmCode = mf.AlgorithmCode,
        signatureValid = true
    });
}).DisableAntiforgery();

app.MapPost("/api/requests/simulate", (SqliteDatabaseService db, CertificateAndZipService certZip) =>
{
    var samplePlain = Encoding.UTF8.GetBytes($"Paquete de prueba LAN · {DateTime.UtcNow:O}");
    var keySha = SHA256.HashData("clave-aes-256-segura"u8.ToArray());
    var nonce = RandomNumberGenerator.GetBytes(12);
    var cipher = new byte[samplePlain.Length];
    var tag = new byte[16];
    using (var aes = new AesGcm(keySha, 16))
        aes.Encrypt(nonce, samplePlain, cipher, tag);

    var encrypted = new byte[12 + 16 + cipher.Length];
    Buffer.BlockCopy(nonce, 0, encrypted, 0, 12);
    Buffer.BlockCopy(tag, 0, encrypted, 12, 16);
    Buffer.BlockCopy(cipher, 0, encrypted, 28, cipher.Length);

    var octet = RandomNumberGenerator.GetInt32(10, 80);
    var fakeIp = $"192.168.1.{octet}:5000";
    var (zipBytes, _, mf) = certZip.CreateSignedZipPackage(
        encrypted,
        "AESGCM",
        "AES-256-GCM",
        "text",
        "prueba_remota.txt",
        samplePlain.Length,
        fakeIp);

    var zipName = CertificateAndZipService.BuildStandardZipName($"NODO{octet}", "AESGCM", mf.EncryptedSha256);
    var reqId = db.AddIncomingRequest(new IncomingRequestRecord
    {
        PacketId = mf.PacketId,
        SourceIp = fakeIp,
        ZipFileName = zipName,
        AlgorithmCode = mf.AlgorithmCode,
        AlgorithmName = mf.Algorithm,
        SignatureValid = true,
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
{
    var ok = db.RejectIncomingRequest(id);
    return ok
        ? Results.Ok(new { rejected = true })
        : Results.BadRequest(new { error = "La solicitud no existe o ya fue procesada." });
});

app.Run();

public partial class Program { }
