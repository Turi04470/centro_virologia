using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Data;

namespace CentroCiberseguridad.Web.Services.Transfer;

public sealed class CertificateAndZipService
{
    public const long MaxPackageBytes = 50L * 1024 * 1024;
    public const long MaxUncompressedBytes = 200L * 1024 * 1024;
    public const double MaxCompressionRatio = 100.0;
    public static readonly TimeSpan TimestampWindow = TimeSpan.FromMinutes(10);

    private static readonly Regex NodeIdRegex = new(@"^EQ[0-9]{2}$", RegexOptions.Compiled);
    private static readonly Regex UuidV4Regex = new(@"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.Compiled);
    private static readonly Regex TimestampRegex = new(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", RegexOptions.Compiled);

    private readonly SqliteDatabaseService _db;
    public static readonly JsonSerializerOptions JsonOpts = new()
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
        return _db.GetOrCreateLocalCertificate(() => GenerateSelfSignedCertificate(SqliteDatabaseService.LocalNodeId, SqliteDatabaseService.LocalTeamNumber));
    }

    public static DigitalCertificateRecord GenerateSelfSignedCertificate(string nodeId, int teamNumber)
    {
        using var rsa = RSA.Create(2048);
        var subject = $"CN={nodeId}, OU=Equipo {teamNumber:D2}, O=Centro de Ciberseguridad, C=MX";
        var req = new CertificateRequest(
            subject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1); // sha256WithRSAEncryption (Sección 7)

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddDays(365);
        using var cert = req.CreateSelfSigned(notBefore, notAfter);

        var pem = cert.ExportCertificatePem();
        var pfxBytes = cert.Export(X509ContentType.Pkcs12, string.Empty);
        var thumbSha256 = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256)); // UPPERCASE hex

        return new DigitalCertificateRecord
        {
            SubjectName = cert.Subject,
            ThumbprintSha256 = thumbSha256,
            SerialNumber = cert.SerialNumber,
            IsLocalNode = true,
            CertificatePem = pem,
            PrivateKeyPfxBase64 = Convert.ToBase64String(pfxBytes),
            NotBeforeUtc = notBefore.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            NotAfterUtc = notAfter.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };
    }

    public static string ComputeThumbprintSha256Upper(string certificatePem)
    {
        using var cert = X509Certificate2.CreateFromPem(certificatePem);
        return Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
    }

    public static string ExtractCommonName(X509Certificate2 cert)
    {
        return cert.GetNameInfo(X509NameType.SimpleName, false) ?? string.Empty;
    }

    // --- Primitiva 8.2: RSA-PSS-SHA256 ---
    public byte[] SignWithLocalKey(byte[] data)
    {
        var rec = GetLocalCertificate();
        return SignWithPfx(data, Convert.FromBase64String(rec.PrivateKeyPfxBase64));
    }

    public static byte[] SignWithPfx(byte[] data, byte[] pfxBytes)
    {
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

    // --- Primitiva 8.3: Sobre Híbrido CC-ENV-1 ---
    public static (CcEnvelope Envelope, byte[] CiphertextBytes) WrapEnvelope(
        byte[] plaintext,
        string recipientNode,
        string recipientCertificatePem,
        string aadId,
        bool includeCiphertextInJson = true)
    {
        using var cert = X509Certificate2.CreateFromPem(recipientCertificatePem);
        using var rsa = cert.GetRSAPublicKey()
            ?? throw new ProtocolException("E-CERT", 422, "Certificado inválido", "El certificado del destinatario no contiene llave pública RSA.");

        var thumb = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
        var cek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        var aad = Encoding.UTF8.GetBytes(aadId);

        using (var aes = new AesGcm(cek, 16))
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        var wrappedKey = rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
        CryptographicOperations.ZeroMemory(cek);

        var env = new CcEnvelope
        {
            Envelope = "CC-ENV-1",
            RecipientNode = recipientNode,
            RecipientThumbprintSha256 = thumb,
            WrappedKeyBase64 = Convert.ToBase64String(wrappedKey),
            NonceBase64 = Convert.ToBase64String(nonce),
            TagBase64 = Convert.ToBase64String(tag),
            CiphertextBase64 = includeCiphertextInJson ? Convert.ToBase64String(ciphertext) : null
        };
        return (env, ciphertext);
    }

    public byte[] UnwrapEnvelope(CcEnvelope env, byte[]? externalCiphertext, string aadId)
    {
        var local = GetLocalCertificate();
        return UnwrapEnvelopeWithPfx(env, externalCiphertext, aadId, local.ThumbprintSha256, Convert.FromBase64String(local.PrivateKeyPfxBase64));
    }

    public static byte[] UnwrapEnvelopeWithPfx(CcEnvelope env, byte[]? externalCiphertext, string aadId, string expectedThumbprintUpper, byte[] pfxBytes)
    {
        if (!string.Equals(env.Envelope, "CC-ENV-1", StringComparison.Ordinal))
            throw new ProtocolException("E-ENV-DECRYPT", 401, "Sobre inválido", "Formato de sobre no soportado (se requiere CC-ENV-1).");

        if (!string.Equals(env.RecipientThumbprintSha256, expectedThumbprintUpper, StringComparison.OrdinalIgnoreCase))
            throw new ProtocolException("E-ENV-RECIPIENT", 401, "Destinatario incorrecto", "El sobre no está dirigido a este nodo.");

        try
        {
            using var cert = X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
            using var rsa = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("No RSA private key.");

            var wrappedKey = Convert.FromBase64String(env.WrappedKeyBase64);
            var nonce = Convert.FromBase64String(env.NonceBase64);
            var tag = Convert.FromBase64String(env.TagBase64);
            var ciphertext = externalCiphertext ?? Convert.FromBase64String(env.CiphertextBase64 ?? string.Empty);

            var cek = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
            var plaintext = new byte[ciphertext.Length];
            var aad = Encoding.UTF8.GetBytes(aadId);

            try
            {
                using var aes = new AesGcm(cek, 16);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
        catch (ProtocolException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ProtocolException("E-ENV-DECRYPT", 401, "Error al abrir sobre", $"No se pudo descifrar el sobre CC-ENV-1: {ex.Message}");
        }
    }

    // --- Primitiva 8.5: Hash canónico de publicParameters ---
    public static (string CanonicalText, string Sha256HexLower) ComputeCanonicalParamsHash(Dictionary<string, string>? publicParams)
    {
        if (publicParams is null || publicParams.Count == 0)
        {
            var emptyHash = Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
            return (string.Empty, emptyHash);
        }

        var ordered = publicParams.OrderBy(kv => kv.Key, StringComparer.Ordinal);
        var canonical = string.Join("\n", ordered.Select(kv => $"{kv.Key}={kv.Value}"));
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        return (canonical, hash);
    }

    // --- Primitiva 8.4: Cadena de firma del manifiesto ---
    public static string BuildSigningString(SignedManifest m)
    {
        return string.Join("|",
            m.Version,
            m.PacketType,
            m.PacketId,
            m.SourceNode,
            m.ProducerNode,
            m.AlgorithmCode,
            m.Operation,
            m.TimestampUtc,
            m.EncryptedSha256,
            m.PublicParametersSha256,
            m.CertificateThumbprintSha256);
    }

    // --- Nomenclatura 9.2 ---
    public static string BuildStandardZipName(string packetType, string sourceNode, string algorithmCode, string timestampUtc, string sha256Hex)
    {
        var cleanNode = new string(sourceNode.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        var cleanAlgo = new string(algorithmCode.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        var dt = DateTime.ParseExact(timestampUtc, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var stamp = dt.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var sha8 = sha256Hex.Length >= 8 ? sha256Hex[..8].ToUpperInvariant() : sha256Hex.ToUpperInvariant();
        return packetType == "result"
            ? $"RES_{cleanNode}_{cleanAlgo}_{stamp}_{sha8}.zip"
            : $"{cleanNode}_{cleanAlgo}_{stamp}_{sha8}.zip";
    }

    public (byte[] ZipBytes, string ZipFileName, SignedManifest Manifest) CreateSignedZipPackage(
        byte[] payloadBytes,
        AlgorithmConfig algo,
        string packetType,
        string operation,
        string payloadMode,
        string originalFileName,
        long originalSizeBytes,
        string contentType = "application/octet-stream",
        string? requestId = null,
        string? producerNode = null,
        string? sourceIp = null,
        Dictionary<string, string>? publicParams = null,
        KeyRefInfo? keyRef = null,
        List<MultipartPartInfo>? parts = null,
        VerificationInfo? verification = null,
        CcEnvelope? resultEnvelope = null,
        string? explicitPacketId = null,
        string? explicitTimestampUtc = null)
    {
        var certRec = GetLocalCertificate();
        var encryptedSha256 = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToLowerInvariant();
        var timestampUtc = explicitTimestampUtc ?? DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var packetId = explicitPacketId ?? Guid.NewGuid().ToString("D").ToLowerInvariant();
        var cleanParams = publicParams ?? new Dictionary<string, string>();
        var (_, paramsHash) = ComputeCanonicalParamsHash(cleanParams);

        var manifest = new SignedManifest
        {
            Version = "2.0",
            PacketType = packetType,
            PacketId = packetId,
            RequestId = requestId,
            SourceNode = SqliteDatabaseService.LocalNodeId,
            SourceTeam = SqliteDatabaseService.LocalTeamNumber,
            SourceIp = sourceIp ?? $"127.0.0.1:{SqliteDatabaseService.LocalHttpPort}",
            ProducerNode = producerNode ?? SqliteDatabaseService.LocalNodeId,
            TimestampUtc = timestampUtc,
            AlgorithmId = algo.AlgorithmId,
            AlgorithmCode = algo.Code,
            AlgorithmName = algo.Name,
            Operation = operation,
            OperationName = operation == "inverse" ? algo.InverseName : algo.ForwardName,
            PayloadMode = payloadMode,
            OriginalFileName = originalFileName,
            OriginalExtension = Path.GetExtension(originalFileName),
            OriginalSizeBytes = originalSizeBytes,
            ContentType = contentType,
            EncryptedSha256 = encryptedSha256,
            EncryptedSizeBytes = payloadBytes.Length,
            Parts = parts,
            KeyRef = keyRef,
            PublicParameters = cleanParams,
            PublicParametersSha256 = paramsHash,
            Verification = verification,
            ResultEnvelope = resultEnvelope,
            CertificateThumbprintSha256 = certRec.ThumbprintSha256,
            SignatureAlgorithm = "RSA-PSS-SHA256"
        };

        var signingString = BuildSigningString(manifest);
        var sigBytes = SignWithLocalKey(Encoding.UTF8.GetBytes(signingString));
        manifest.ManifestSignatureBase64 = Convert.ToBase64String(sigBytes);

        var dataEntryName = packetType == "result" ? "resultado.enc" : "datos.enc";
        var zipBytes = BuildZipArchive(dataEntryName, payloadBytes, certRec.CertificatePem, manifest);
        var zipName = BuildStandardZipName(packetType, manifest.SourceNode, manifest.AlgorithmCode, timestampUtc, encryptedSha256);
        return (zipBytes, zipName, manifest);
    }

    // --- Sección 9.6: Reenvío ---
    public (byte[] ZipBytes, string ZipFileName, SignedManifest Manifest) RepackageForForwarding(byte[] originalZipBytes, string localIpWithPort)
    {
        var val = ValidateZipPackage(originalZipBytes, checkReplay: false, checkTimestamp: false, checkDirectoryTrust: false);
        if (!val.IsValid || val.Manifest is null)
            throw new ProtocolException(val.ErrorCode, val.HttpStatusCode, "Paquete inválido", val.ErrorMessage);

        var old = val.Manifest;
        var algo = _db.GetAlgorithm(old.AlgorithmCode)
            ?? throw new ProtocolException("E-ALGORITHM", 400, "Algoritmo desconocido", $"Algoritmo '{old.AlgorithmCode}' no existe en el diccionario.");

        return CreateSignedZipPackage(
            val.PayloadBytes,
            algo,
            old.PacketType,
            old.Operation,
            old.PayloadMode,
            old.OriginalFileName,
            old.OriginalSizeBytes,
            old.ContentType,
            requestId: old.RequestId,
            producerNode: old.ProducerNode,
            sourceIp: localIpWithPort,
            publicParams: old.PublicParameters,
            keyRef: old.KeyRef,
            parts: old.Parts,
            verification: old.Verification,
            resultEnvelope: old.ResultEnvelope);
    }

    // --- Sección 13.1: Validación de 14 pasos ---
    public ZipValidationResult ValidateZipPackage(
        byte[] zipBytes,
        bool checkReplay = true,
        bool checkTimestamp = true,
        bool checkDirectoryTrust = true,
        string? expectedPacketType = null)
    {
        // 1. Cuerpo <= 50 MB
        if (zipBytes.Length > MaxPackageBytes)
            return Fail("E-SIZE", 413, "El paquete ZIP supera el límite de 50 MB.");

        try
        {
            using var ms = new MemoryStream(zipBytes);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            // 3. Exactamente 3 entradas en raíz sin rutas ni carpetas
            if (archive.Entries.Count != 3)
                return Fail("E-ZIP-STRUCTURE", 400, $"El ZIP debe contener exactamente 3 archivos en la raíz (contiene {archive.Entries.Count}).");

            foreach (var e in archive.Entries)
            {
                if (e.FullName.Contains('/') || e.FullName.Contains('\\') || e.FullName.Contains(".."))
                    return Fail("E-ZIP-STRUCTURE", 400, $"Ruta no permitida dentro del ZIP: '{e.FullName}'.");
            }

            var certEntry = archive.GetEntry("certificado.pem");
            var manifestEntry = archive.GetEntry("manifest.json");
            var dataEntry = archive.GetEntry("datos.enc") ?? archive.GetEntry("resultado.enc");

            if (certEntry is null || manifestEntry is null || dataEntry is null)
                return Fail("E-ZIP-STRUCTURE", 400, "El ZIP debe contener datos.enc (o resultado.enc), certificado.pem y manifest.json.");

            // 4. Anti ZIP-bomb (<= 200 MB descomprimido y razón <= 100:1)
            long totalUncompressed = 0;
            foreach (var e in archive.Entries)
            {
                totalUncompressed += e.Length;
                if (e.CompressedLength > 0 && (double)e.Length / e.CompressedLength > MaxCompressionRatio)
                    return Fail("E-ZIP-BOMB", 400, "Razón de compresión excesiva (>100:1).");
            }
            if (totalUncompressed > MaxUncompressedBytes)
                return Fail("E-ZIP-BOMB", 400, "Tamaño descomprimido excede 200 MB.");

            var payloadBytes = ReadEntryBytesSafe(dataEntry, MaxUncompressedBytes);
            var certPem = Encoding.UTF8.GetString(ReadEntryBytesSafe(certEntry, 1024 * 1024));
            var manifestJson = Encoding.UTF8.GetString(ReadEntryBytesSafe(manifestEntry, 2 * 1024 * 1024));

            // 5. manifest.json válido y campos obligatorios
            SignedManifest? mf;
            try
            {
                mf = JsonSerializer.Deserialize<SignedManifest>(manifestJson, JsonOpts);
            }
            catch (JsonException)
            {
                return Fail("E-MANIFEST", 400, "JSON inválido en manifest.json.");
            }

            if (mf is null ||
                string.IsNullOrWhiteSpace(mf.PacketId) || !UuidV4Regex.IsMatch(mf.PacketId) ||
                string.IsNullOrWhiteSpace(mf.SourceNode) || !NodeIdRegex.IsMatch(mf.SourceNode) ||
                string.IsNullOrWhiteSpace(mf.ProducerNode) || !NodeIdRegex.IsMatch(mf.ProducerNode) ||
                string.IsNullOrWhiteSpace(mf.TimestampUtc) || !TimestampRegex.IsMatch(mf.TimestampUtc) ||
                string.IsNullOrWhiteSpace(mf.EncryptedSha256) ||
                string.IsNullOrWhiteSpace(mf.PublicParametersSha256) ||
                string.IsNullOrWhiteSpace(mf.CertificateThumbprintSha256) ||
                string.IsNullOrWhiteSpace(mf.ManifestSignatureBase64) ||
                (mf.PacketType is not ("package" or "result")) ||
                (mf.Operation is not ("forward" or "inverse")))
            {
                return Fail("E-MANIFEST", 400, "manifest.json con campos obligatorios faltantes o formato inválido.");
            }

            // Verificar correspondencia datos.enc vs resultado.enc
            if (mf.PacketType == "package" && dataEntry.FullName != "datos.enc")
                return Fail("E-ZIP-STRUCTURE", 400, "Un paquete tipo 'package' debe incluir datos.enc.");
            if (mf.PacketType == "result" && dataEntry.FullName != "resultado.enc")
                return Fail("E-ZIP-STRUCTURE", 400, "Un paquete tipo 'result' debe incluir resultado.enc.");
            if (expectedPacketType is not null && mf.PacketType != expectedPacketType)
                return Fail("E-MANIFEST", 400, $"Se esperaba packetType='{expectedPacketType}'.");

            // 6. version = "2.0"
            if (!string.Equals(mf.Version, "2.0", StringComparison.Ordinal))
                return Fail("E-VERSION", 400, $"Versión de protocolo no soportada: '{mf.Version}' (se requiere '2.0').");

            // 7. algorithmId y algorithmCode coinciden con tabla 4.1
            var dictAlgo = _db.GetAlgorithm(mf.AlgorithmCode);
            if (dictAlgo is null || dictAlgo.AlgorithmId != mf.AlgorithmId)
                return Fail("E-ALGORITHM", 400, $"algorithmId ({mf.AlgorithmId}) y algorithmCode ({mf.AlgorithmCode}) no coinciden con la tabla 4.1.");

            // 8. SHA-256 de datos.enc / resultado.enc (comparación en tiempo constante)
            var actualSha = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToLowerInvariant();
            if (!FixedTimeEqualsAscii(actualSha, mf.EncryptedSha256))
                return Fail("E-HASH", 422, "El SHA-256 del contenido no coincide con encryptedSha256.");

            // 9. publicParametersSha256 correcto
            var (_, expectedParamsHash) = ComputeCanonicalParamsHash(mf.PublicParameters);
            if (!FixedTimeEqualsAscii(expectedParamsHash, mf.PublicParametersSha256))
                return Fail("E-PARAMS-HASH", 422, "publicParametersSha256 no coincide con el hash canónico de publicParameters.");

            // 10. certificado.pem X.509 válido, RSA-2048, CN = sourceNode, vigente
            X509Certificate2 cert;
            try
            {
                cert = X509Certificate2.CreateFromPem(certPem);
            }
            catch
            {
                return Fail("E-CERT", 422, "certificado.pem no es un certificado X.509 PEM válido.");
            }

            using (cert)
            {
                using var pubRsa = cert.GetRSAPublicKey();
                if (pubRsa is null || pubRsa.KeySize < 2048)
                    return Fail("E-CERT", 422, "El certificado debe usar una llave RSA de al menos 2048 bits.");

                var cn = ExtractCommonName(cert);
                if (!string.Equals(cn, mf.SourceNode, StringComparison.Ordinal))
                    return Fail("E-CERT", 422, $"El CN del certificado ('{cn}') no coincide con sourceNode ('{mf.SourceNode}').");

                var now = DateTime.UtcNow;
                if (now < cert.NotBefore.ToUniversalTime() || now > cert.NotAfter.ToUniversalTime())
                    return Fail("E-CERT", 422, "El certificado X.509 está vencido o aún no es vigente.");

                // 11. Huella del certificado == certificateThumbprintSha256
                var actualThumb = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
                if (!FixedTimeEqualsAscii(actualThumb, mf.CertificateThumbprintSha256))
                    return Fail("E-CERT-THUMBPRINT", 422, "La huella del certificado no coincide con certificateThumbprintSha256.");

                // 12. Firma válida sobre cadena 8.4
                byte[] sigBytes;
                try { sigBytes = Convert.FromBase64String(mf.ManifestSignatureBase64); }
                catch { return Fail("E-SIGNATURE", 422, "manifestSignatureBase64 no es Base64 válido."); }

                var signingBytes = Encoding.UTF8.GetBytes(BuildSigningString(mf));
                if (!pubRsa.VerifyData(signingBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                    return Fail("E-SIGNATURE", 422, "Firma RSA-PSS-SHA256 del manifiesto inválida.");

                // 13. timestampUtc dentro de +-10 min
                if (checkTimestamp)
                {
                    var ts = DateTime.ParseExact(mf.TimestampUtc, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
                    if (Math.Abs((DateTime.UtcNow - ts).TotalMinutes) > TimestampWindow.TotalMinutes)
                        return Fail("E-TIMESTAMP", 422, "timestampUtc fuera de la ventana permitida de ±10 minutos.");
                }

                // 14. packetId no repetido
                if (checkReplay && !_db.TryRegisterSeenId(mf.PacketId, "packet"))
                    return Fail("E-DUPLICATE", 409, $"packetId repetido: {mf.PacketId}.");

                // Confianza TOFU en directorio
                var trustStatus = "Firma OK";
                if (checkDirectoryTrust && !string.Equals(mf.SourceNode, SqliteDatabaseService.LocalNodeId, StringComparison.Ordinal))
                {
                    var dirNode = _db.GetDirectoryNode(mf.SourceNode);
                    if (dirNode is null || string.IsNullOrEmpty(dirNode.PinnedThumbprintSha256))
                    {
                        trustStatus = "Remitente no confirmado";
                    }
                    else if (!FixedTimeEqualsAscii(dirNode.PinnedThumbprintSha256, actualThumb))
                    {
                        return Fail("E-CERT-UNTRUSTED", 403, $"La huella de {mf.SourceNode} no coincide con la huella fijada en el directorio.");
                    }
                }

                return new ZipValidationResult
                {
                    IsValid = true,
                    HttpStatusCode = 202,
                    TrustStatus = trustStatus,
                    Manifest = mf,
                    PayloadBytes = payloadBytes,
                    CertificatePem = certPem
                };
            }
        }
        catch (InvalidDataException)
        {
            return Fail("E-ZIP-INVALID", 400, "El archivo enviado no es un ZIP válido.");
        }
        catch (Exception ex)
        {
            return Fail("E-ZIP-INVALID", 400, $"Error al leer el paquete ZIP: {ex.Message}");
        }
    }

    public static byte[] BuildZipArchive(string dataEntryName, byte[] payloadBytes, string certPem, SignedManifest manifest)
    {
        var manifestJson = JsonSerializer.Serialize(manifest, JsonOpts);
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, dataEntryName, payloadBytes);
            WriteEntry(archive, "certificado.pem", Encoding.UTF8.GetBytes(certPem));
            WriteEntry(archive, "manifest.json", Encoding.UTF8.GetBytes(manifestJson));
        }
        return ms.ToArray();
    }

    public static bool FixedTimeEqualsAscii(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    private static ZipValidationResult Fail(string code, int status, string message) => new()
    {
        IsValid = false,
        ErrorCode = code,
        HttpStatusCode = status,
        ErrorMessage = message,
        TrustStatus = "Inválida"
    };

    private static void WriteEntry(ZipArchive archive, string name, byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var s = entry.Open();
        s.Write(bytes, 0, bytes.Length);
    }

    private static byte[] ReadEntryBytesSafe(ZipArchiveEntry entry, long maxBytes)
    {
        using var s = entry.Open();
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        long total = 0;
        int read;
        while ((read = s.Read(buf, 0, buf.Length)) > 0)
        {
            total += read;
            if (total > maxBytes) throw new ProtocolException("E-ZIP-BOMB", 400, "ZIP Bomb", "Tamaño descomprimido excedido.");
            ms.Write(buf, 0, read);
        }
        return ms.ToArray();
    }
}
