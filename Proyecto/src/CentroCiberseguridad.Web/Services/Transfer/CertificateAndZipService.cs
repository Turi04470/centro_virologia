using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Data;

namespace CentroCiberseguridad.Web.Services.Transfer;

public sealed class CertificateAndZipService
{
    private readonly SqliteDatabaseService _db;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public CertificateAndZipService(SqliteDatabaseService db)
    {
        _db = db;
    }

    public DigitalCertificateRecord GetLocalCertificate()
    {
        return _db.GetOrCreateLocalCertificate(GenerateSelfSignedCertificate);
    }

    private static DigitalCertificateRecord GenerateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=NODO-04, O=CentroCiberseguridad",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddYears(1);
        using var cert = req.CreateSelfSigned(notBefore, notAfter);

        var pem = cert.ExportCertificatePem();
        var pfxBytes = cert.Export(X509ContentType.Pkcs12, string.Empty);
        var thumbSha256 = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));

        return new DigitalCertificateRecord
        {
            SubjectName = cert.Subject,
            ThumbprintSha256 = thumbSha256,
            SerialNumber = cert.SerialNumber,
            IsLocalNode = true,
            CertificatePem = pem,
            PrivateKeyPfxBase64 = Convert.ToBase64String(pfxBytes),
            NotBeforeUtc = notBefore.UtcDateTime.ToString("yyyy-MM-dd"),
            NotAfterUtc = notAfter.UtcDateTime.ToString("yyyy-MM-dd")
        };
    }

    public byte[] SignWithLocalKey(byte[] data)
    {
        var rec = GetLocalCertificate();
        var pfxBytes = Convert.FromBase64String(rec.PrivateKeyPfxBase64);
        using var cert = X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
        using var rsa = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("No RSA private key.");
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool VerifyWithPem(byte[] data, byte[] signature, string certificatePem)
    {
        try
        {
            using var cert = X509Certificate2.CreateFromPem(certificatePem);
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is null) return false;
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch
        {
            return false;
        }
    }

    public static string BuildStandardZipName(string nodeId, string algorithmCode, string sha256Hex)
    {
        var cleanNode = new string(nodeId.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        if (string.IsNullOrEmpty(cleanNode)) cleanNode = "NODO04";
        var cleanAlgo = new string(algorithmCode.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var sha8 = sha256Hex.Length >= 8 ? sha256Hex[..8].ToUpperInvariant() : sha256Hex.ToUpperInvariant();
        return $"{cleanNode}_{cleanAlgo}_{stamp}_{sha8}.zip";
    }

    public (byte[] ZipBytes, string ZipFileName, SignedManifest Manifest) CreateSignedZipPackage(
        byte[] encryptedBytes,
        string algorithmCode,
        string algorithmName,
        string payloadMode,
        string originalFileName,
        long originalSizeBytes,
        string sourceIp = "127.0.0.1:5000",
        Dictionary<string, string>? publicParams = null)
    {
        var certRec = GetLocalCertificate();
        var encryptedSha256 = Convert.ToHexString(SHA256.HashData(encryptedBytes)).ToLowerInvariant();
        var timestampUtc = DateTime.UtcNow.ToString("O");
        var canonical = Encoding.UTF8.GetBytes($"{encryptedSha256}|{certRec.ThumbprintSha256}|{timestampUtc}");
        var sigBytes = SignWithLocalKey(canonical);

        var manifest = new SignedManifest
        {
            Version = "1.0",
            PacketId = Guid.NewGuid().ToString(),
            SourceNode = "NODO-04",
            SourceIp = sourceIp,
            TimestampUtc = timestampUtc,
            Algorithm = algorithmName,
            AlgorithmCode = algorithmCode.ToUpperInvariant(),
            PayloadMode = payloadMode,
            OriginalFileName = originalFileName,
            OriginalExtension = Path.GetExtension(originalFileName),
            OriginalSizeBytes = originalSizeBytes,
            EncryptedSha256 = encryptedSha256,
            PublicParameters = publicParams ?? new Dictionary<string, string>(),
            CertificateThumbprintSha256 = certRec.ThumbprintSha256,
            SignatureAlgorithm = "RSA-PSS-SHA256",
            ManifestSignatureBase64 = Convert.ToBase64String(sigBytes)
        };

        var manifestJson = JsonSerializer.Serialize(manifest, JsonOpts);
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "datos.enc", encryptedBytes);
            WriteEntry(archive, "certificado.pem", Encoding.UTF8.GetBytes(certRec.CertificatePem));
            WriteEntry(archive, "manifest.json", Encoding.UTF8.GetBytes(manifestJson));
        }

        var zipBytes = ms.ToArray();
        var zipName = BuildStandardZipName("NODO04", algorithmCode, encryptedSha256);
        return (zipBytes, zipName, manifest);
    }

    public ZipValidationResult ValidateZipPackage(byte[] zipBytes)
    {
        try
        {
            using var ms = new MemoryStream(zipBytes);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            var dataEntry = archive.GetEntry("datos.enc");
            var certEntry = archive.GetEntry("certificado.pem");
            var manifestEntry = archive.GetEntry("manifest.json");

            if (dataEntry is null || certEntry is null || manifestEntry is null)
            {
                return new ZipValidationResult
                {
                    IsValid = false,
                    HttpStatusCode = 400,
                    ErrorMessage = "El ZIP debe contener datos.enc, certificado.pem y manifest.json en su raíz."
                };
            }

            var encryptedBytes = ReadEntryBytes(dataEntry);
            var certPem = Encoding.UTF8.GetString(ReadEntryBytes(certEntry));
            var manifestJson = Encoding.UTF8.GetString(ReadEntryBytes(manifestEntry));

            var manifest = JsonSerializer.Deserialize<SignedManifest>(manifestJson, JsonOpts);
            if (manifest is null || string.IsNullOrWhiteSpace(manifest.EncryptedSha256) || string.IsNullOrWhiteSpace(manifest.ManifestSignatureBase64))
            {
                return new ZipValidationResult
                {
                    IsValid = false,
                    HttpStatusCode = 400,
                    ErrorMessage = "manifest.json inválido o incompleto."
                };
            }

            var actualSha256 = Convert.ToHexString(SHA256.HashData(encryptedBytes)).ToLowerInvariant();
            if (!string.Equals(actualSha256, manifest.EncryptedSha256, StringComparison.OrdinalIgnoreCase))
            {
                return new ZipValidationResult
                {
                    IsValid = false,
                    HttpStatusCode = 422,
                    ErrorMessage = "Integridad inválida: el SHA-256 de datos.enc no coincide con manifest.json."
                };
            }

            using var cert = X509Certificate2.CreateFromPem(certPem);
            var certThumb = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
            var canonical = Encoding.UTF8.GetBytes($"{manifest.EncryptedSha256}|{certThumb}|{manifest.TimestampUtc}");
            var sigBytes = Convert.FromBase64String(manifest.ManifestSignatureBase64);

            if (!VerifyWithPem(canonical, sigBytes, certPem))
            {
                return new ZipValidationResult
                {
                    IsValid = false,
                    HttpStatusCode = 422,
                    ErrorMessage = "Firma digital inválida frente a certificado.pem."
                };
            }

            return new ZipValidationResult
            {
                IsValid = true,
                HttpStatusCode = 202,
                Manifest = manifest,
                EncryptedBytes = encryptedBytes,
                CertificatePem = certPem
            };
        }
        catch (InvalidDataException)
        {
            return new ZipValidationResult
            {
                IsValid = false,
                HttpStatusCode = 400,
                ErrorMessage = "El archivo enviado no es un ZIP válido."
            };
        }
        catch (JsonException)
        {
            return new ZipValidationResult
            {
                IsValid = false,
                HttpStatusCode = 400,
                ErrorMessage = "Error de formato JSON en manifest.json."
            };
        }
        catch (Exception ex)
        {
            return new ZipValidationResult
            {
                IsValid = false,
                HttpStatusCode = 422,
                ErrorMessage = $"Error validando paquete ZIP: {ex.Message}"
            };
        }
    }

    private static void WriteEntry(ZipArchive archive, string name, byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var s = entry.Open();
        s.Write(bytes, 0, bytes.Length);
    }

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
