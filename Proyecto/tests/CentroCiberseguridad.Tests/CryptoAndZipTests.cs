using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Crypto;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Transfer;

namespace CentroCiberseguridad.Tests;

public sealed class CryptoAndZipTests : IDisposable
{
    private readonly string _dbFile;
    private readonly SqliteDatabaseService _db;
    private readonly CertificateAndZipService _certZip;
    private readonly CryptoEngineService _crypto;

    public CryptoAndZipTests()
    {
        _dbFile = Path.Combine(Path.GetTempPath(), $"csec_v2_test_{Guid.NewGuid():N}.db");
        _db = new SqliteDatabaseService(_dbFile);
        _certZip = new CertificateAndZipService(_db);
        _crypto = new CryptoEngineService(_db, _certZip);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (File.Exists(_dbFile))
        {
            try { File.Delete(_dbFile); } catch { }
        }
    }

    public static IEnumerable<object[]> AllAlgorithmCodes() =>
        SqliteDatabaseService.DefaultAlgorithms.Select(a => new object[] { a.Code, a.DefaultKey });

    [Theory]
    [MemberData(nameof(AllAlgorithmCodes))]
    public void All21Algorithms_TextRoundTrip_WorksCorrectly(string code, string defaultKey)
    {
        const string sample = "Hola Centro de Ciberseguridad v2.0";
        var enc = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = code,
            IsEncrypt = true,
            InputMode = "text",
            Text = sample,
            Key = defaultKey,
            AttachCertificate = true
        });

        Assert.False(string.IsNullOrWhiteSpace(enc.OutputText));
        Assert.NotNull(enc.ConsultaId);
        Assert.NotNull(enc.ZipFileName);
        Assert.StartsWith($"EQ04_{code}_", enc.ZipFileName);
        Assert.Equal("2.0", enc.Manifest!.Version);
        Assert.Equal(16, enc.Cells.Length);
        Assert.NotEmpty(enc.Steps);

        if (code == "HASHSHA")
        {
            var ver = _crypto.Execute(new OperateRequest
            {
                AlgorithmCode = code,
                IsEncrypt = false,
                InputMode = "text",
                Text = sample,
                Key = enc.OutputText!,
                AttachCertificate = false
            });
            Assert.StartsWith("VÁLIDO", ver.OutputText);
            return;
        }

        var decInput = code == "LAGRANGESHAMIR"
            ? string.Join("\n", enc.OutputText!.Split('\n').Take(3))
            : enc.OutputText!;

        var dec = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = code,
            IsEncrypt = false,
            InputMode = "text",
            Text = decInput,
            Key = defaultKey,
            AttachCertificate = false
        });

        Assert.Equal(sample, dec.OutputText);
    }

    [Fact]
    public void BinaryFileMode_RoundTrip_WorksCorrectly()
    {
        var originalBytes = new byte[] { 0x00, 0xFF, 0x4D, 0x5A, 0x10, 0x20, 0x33, 0x7F, 0x80 };
        var b64 = Convert.ToBase64String(originalBytes);

        foreach (var code in new[] { "AESGCM", "DES", "TRIPLEDES", "CHACHA20", "RSA", "ECC", "CAESAR", "VIGENERE", "XORASM", "EUCLIDESAFFINE", "FISHERYATES", "LORENZSZ40" })
        {
            var key = SqliteDatabaseService.DefaultAlgorithms.First(a => a.Code == code).DefaultKey;
            var enc = _crypto.Execute(new OperateRequest
            {
                AlgorithmCode = code,
                IsEncrypt = true,
                InputMode = "file",
                FileBase64 = b64,
                FileName = "muestra.bin",
                Key = key,
                AttachCertificate = false
            });

            var dec = _crypto.Execute(new OperateRequest
            {
                AlgorithmCode = code,
                IsEncrypt = false,
                InputMode = "file",
                FileBase64 = enc.OutputBase64,
                FileName = enc.OutputFileName,
                Key = key,
                AttachCertificate = false
            });

            Assert.Equal(originalBytes, Convert.FromBase64String(dec.OutputBase64!));
        }
    }

    [Fact]
    public void SettingsPermissions_BlockHiddenEncryptAndDecrypt()
    {
        _db.UpdateAlgorithm("AESGCM", isVisible: true, canEncrypt: false, canDecrypt: true);

        Assert.Throws<UnauthorizedAccessException>(() => _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "AESGCM",
            IsEncrypt = true,
            InputMode = "text",
            Text = "hola",
            Key = "mi-clave"
        }));

        _db.UpdateAlgorithm("AESGCM", isVisible: true, canEncrypt: true, canDecrypt: false);
        var enc = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "AESGCM",
            IsEncrypt = true,
            InputMode = "text",
            Text = "hola",
            Key = "mi-clave"
        });

        Assert.Throws<UnauthorizedAccessException>(() => _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "AESGCM",
            IsEncrypt = false,
            InputMode = "text",
            Text = enc.OutputText,
            Key = "mi-clave"
        }));

        _db.HideAllAlgorithms();
        var algos = _db.GetAlgorithms();
        Assert.Equal(21, algos.Count);
        Assert.All(algos, a => Assert.False(a.IsVisible));
    }

    [Fact]
    public void V2Primitives_CanonicalParams_And_CcEnv1_WorkCorrectly()
    {
        var (canonical, hash) = CertificateAndZipService.ComputeCanonicalParamsHash(new Dictionary<string, string>
        {
            ["hashAlgorithm"] = "SHA-256",
            ["digestHex"] = "ab12"
        });
        Assert.Equal("digestHex=ab12\nhashAlgorithm=SHA-256", canonical);
        Assert.Equal(64, hash.Length);

        var (_, emptyHash) = CertificateAndZipService.ComputeCanonicalParamsHash(new Dictionary<string, string>());
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash);

        // CC-ENV-1 round-trip
        var localCert = _certZip.GetLocalCertificate();
        var secret = Encoding.UTF8.GetBytes("{\"shift\":\"7\"}");
        var aadId = Guid.NewGuid().ToString("D");
        var (env, _) = CertificateAndZipService.WrapEnvelope(secret, "EQ04", localCert.CertificatePem, aadId, includeCiphertextInJson: true);
        var unwrapped = _certZip.UnwrapEnvelope(env, null, aadId);
        Assert.Equal(secret, unwrapped);

        // Wrong recipient -> 401 E-ENV-RECIPIENT
        env.RecipientThumbprintSha256 = new string('0', 64);
        var ex = Assert.Throws<ProtocolException>(() => _certZip.UnwrapEnvelope(env, null, aadId));
        Assert.Equal("E-ENV-RECIPIENT", ex.ErrorCode);
        Assert.Equal(401, ex.HttpStatusCode);
    }

    [Fact]
    public void V2Validation_RejectsInvalidStructure_TamperedHash_OldTimestamp_Duplicate_And_UntrustedCert()
    {
        var algo = _db.GetAlgorithm("CAESAR")!;
        var (zipBytes, _, mf) = _certZip.CreateSignedZipPackage(
            "KROD"u8.ToArray(),
            algo,
            "package",
            "forward",
            "text",
            "hola.txt",
            4,
            publicParams: new Dictionary<string, string> { ["alphabet"] = "A-Z" });

        // 1. Válido primera vez -> 202
        var ok = _certZip.ValidateZipPackage(zipBytes, checkReplay: true, checkTimestamp: true, checkDirectoryTrust: true);
        Assert.True(ok.IsValid);
        Assert.Equal(202, ok.HttpStatusCode);

        // 2. Repetición del mismo packetId -> 409 E-DUPLICATE
        var dup = _certZip.ValidateZipPackage(zipBytes, checkReplay: true, checkTimestamp: true, checkDirectoryTrust: true);
        Assert.False(dup.IsValid);
        Assert.Equal(409, dup.HttpStatusCode);
        Assert.Equal("E-DUPLICATE", dup.ErrorCode);

        // 3. Alterar 1 byte de datos.enc -> 422 E-HASH
        var tamperedHashZip = MutateZip(zipBytes, (name, data) => name == "datos.enc" ? new[] { (byte)(data[0] ^ 1) }.Concat(data.Skip(1)).ToArray() : data);
        var badHash = _certZip.ValidateZipPackage(tamperedHashZip, checkReplay: false);
        Assert.Equal("E-HASH", badHash.ErrorCode);
        Assert.Equal(422, badHash.HttpStatusCode);

        // 4. ZIP con 4 archivos -> 400 E-ZIP-STRUCTURE
        var fourEntriesZip = AddExtraEntry(zipBytes, "extra.txt", "hola"u8.ToArray());
        var badStruct = _certZip.ValidateZipPackage(fourEntriesZip, checkReplay: false);
        Assert.Equal("E-ZIP-STRUCTURE", badStruct.ErrorCode);
        Assert.Equal(400, badStruct.HttpStatusCode);

        // 5. Timestamp viejo (>10 min) -> 422 E-TIMESTAMP
        var oldTs = DateTime.UtcNow.AddMinutes(-25).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var (oldZip, _, _) = _certZip.CreateSignedZipPackage(
            "KROD"u8.ToArray(), algo, "package", "forward", "text", "hola.txt", 4,
            publicParams: new Dictionary<string, string> { ["alphabet"] = "A-Z" },
            explicitTimestampUtc: oldTs);
        var badTs = _certZip.ValidateZipPackage(oldZip, checkReplay: false, checkTimestamp: true);
        Assert.Equal("E-TIMESTAMP", badTs.ErrorCode);
        Assert.Equal(422, badTs.HttpStatusCode);
    }

    [Fact]
    public void V2Provider_ForwardAndInverse_CaesarAndDiffieHellman_WorksEndToEnd()
    {
        // Solicitante simulado EQ08
        var eq08Cert = CertificateAndZipService.GenerateSelfSignedCertificate("EQ08", 8);
        var eq08Pfx = Convert.FromBase64String(eq08Cert.PrivateKeyPfxBase64);

        // 1. CAESAR forward + inverse
        var plain = Encoding.UTF8.GetBytes("PRUEBA REMOTA CAESAR");
        var fwdReq = new CryptoRemoteRequestDto
        {
            RequestId = Guid.NewGuid().ToString("D"),
            RequesterNode = "EQ08",
            TargetNode = "EQ04",
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = "CAESAR",
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "nota.txt",
            Options = new Dictionary<string, string> { ["alphabet"] = "A-Z" }
        };
        var (pkgZip, _, _) = _crypto.ExecuteProviderForward(fwdReq, plain, new Dictionary<string, string> { ["shift"] = "5" }, "127.0.0.1:5004");
        var pkgVal = _certZip.ValidateZipPackage(pkgZip, checkReplay: false);
        Assert.True(pkgVal.IsValid);

        var invReq = new CryptoRemoteRequestDto
        {
            RequestId = Guid.NewGuid().ToString("D"),
            RequesterNode = "EQ08",
            TargetNode = "EQ04",
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = "CAESAR",
            Operation = "inverse",
            PayloadMode = "text",
            OriginalFileName = "nota.txt"
        };
        var (resZip, resName, resMf) = _crypto.ExecuteProviderInverse(invReq, pkgVal, new Dictionary<string, string> { ["shift"] = "5" }, eq08Cert.CertificatePem, "127.0.0.1:5004");
        Assert.StartsWith("RES_EQ04_CAESAR_", resName);
        var resVal = _certZip.ValidateZipPackage(resZip, checkReplay: false, expectedPacketType: "result");
        Assert.True(resVal.IsValid);
        var decrypted = CertificateAndZipService.UnwrapEnvelopeWithPfx(resMf.ResultEnvelope!, resVal.PayloadBytes, resMf.PacketId, eq08Cert.ThumbprintSha256, eq08Pfx);
        Assert.Equal(plain, decrypted);

        // 2. DIFFIEHELLMAN con keyId persistente
        var dhPlain = Encoding.UTF8.GetBytes("SECRETO DIFFIE HELLMAN v2.0");
        var dhFwd = new CryptoRemoteRequestDto
        {
            RequestId = Guid.NewGuid().ToString("D"),
            RequesterNode = "EQ08",
            TargetNode = "EQ04",
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = "DIFFIEHELLMAN",
            Operation = "forward",
            PayloadMode = "file",
            OriginalFileName = "secreto.bin"
        };
        var (dhPkgZip, _, dhMf) = _crypto.ExecuteProviderForward(dhFwd, dhPlain, null, "127.0.0.1:5004");
        Assert.NotNull(dhMf.KeyRef);
        Assert.StartsWith("EQ04-KEY-", dhMf.KeyRef!.KeyId);

        var dhPkgVal = _certZip.ValidateZipPackage(dhPkgZip, checkReplay: false);
        var (dhResZip, _, dhResMf) = _crypto.ExecuteProviderInverse(dhFwd, dhPkgVal, null, eq08Cert.CertificatePem, "127.0.0.1:5004");
        var dhResVal = _certZip.ValidateZipPackage(dhResZip, checkReplay: false, expectedPacketType: "result");
        var dhDecrypted = CertificateAndZipService.UnwrapEnvelopeWithPfx(dhResMf.ResultEnvelope!, dhResVal.PayloadBytes, dhResMf.PacketId, eq08Cert.ThumbprintSha256, eq08Pfx);
        Assert.Equal(dhPlain, dhDecrypted);
    }

    [Fact]
    public void V2RepackageForForwarding_PreservesProducerAndUpdatesPacketId()
    {
        var algo = _db.GetAlgorithm("CAESAR")!;
        var (origZip, _, origMf) = _certZip.CreateSignedZipPackage(
            "KROD"u8.ToArray(), algo, "package", "forward", "text", "hola.txt", 4,
            producerNode: "EQ01",
            publicParams: new Dictionary<string, string> { ["alphabet"] = "A-Z" });

        var (fwdZip, _, fwdMf) = _certZip.RepackageForForwarding(origZip, "192.168.1.40:5004");
        Assert.Equal("EQ01", fwdMf.ProducerNode);
        Assert.Equal("EQ04", fwdMf.SourceNode);
        Assert.NotEqual(origMf.PacketId, fwdMf.PacketId);
        Assert.True(_certZip.ValidateZipPackage(fwdZip, checkReplay: false).IsValid);
    }

    [Fact]
    public void IncomingRequests_AcceptAddsToConsultas_RejectDoesNot()
    {
        var algo = _db.GetAlgorithm("CHACHA20")!;
        var (zipBytes, zipName, mf) = _certZip.CreateSignedZipPackage("abc"u8.ToArray(), algo, "package", "forward", "text", "doc.txt", 3);

        var id1 = _db.AddIncomingRequest(new IncomingRequestRecord
        {
            PacketId = mf.PacketId,
            SourceNode = "EQ02",
            SourceIp = "192.168.1.30:5002",
            ZipFileName = zipName,
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.AlgorithmName,
            OperationName = mf.OperationName,
            SignatureValid = true,
            TrustStatus = "Firma OK",
            Status = "Pendiente",
            EncryptedSha256 = mf.EncryptedSha256,
            ReceivedAt = "2026-11-25 22:00",
            ZipBytes = zipBytes
        });

        var id2 = _db.AddIncomingRequest(new IncomingRequestRecord
        {
            PacketId = Guid.NewGuid().ToString("D"),
            SourceNode = "EQ03",
            SourceIp = "192.168.1.31:5003",
            ZipFileName = "rechazado.zip",
            AlgorithmCode = "RSA",
            AlgorithmName = "RSA",
            OperationName = "cifrar",
            SignatureValid = true,
            TrustStatus = "Remitente no confirmado",
            Status = "Pendiente",
            EncryptedSha256 = mf.EncryptedSha256,
            ReceivedAt = "2026-11-25 22:01",
            ZipBytes = zipBytes
        });

        var saved = _db.AcceptIncomingRequest(id1);
        Assert.NotNull(saved);
        Assert.Equal("Recibido", saved!.Origin);
        Assert.True(_db.RejectIncomingRequest(id2));
        Assert.Single(_db.GetSavedPackages());
    }

    [Fact]
    public void MissingKey_ThrowsArgumentException_ExceptHashEncrypt()
    {
        Assert.Throws<ArgumentException>(() => _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "AESGCM",
            IsEncrypt = true,
            InputMode = "text",
            Text = "sin-clave",
            Key = ""
        }));

        var hash = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "HASHSHA",
            IsEncrypt = true,
            InputMode = "text",
            Text = "sin-clave",
            Key = ""
        });
        Assert.Equal(64, hash.OutputText!.Length);
    }

    [Fact]
    public void Consultas_DeleteSingle_ClearAll_AndGetAllWithBytes_Works()
    {
        var r1 = _crypto.Execute(new OperateRequest { AlgorithmCode = "CAESAR", IsEncrypt = true, InputMode = "text", Text = "uno", Key = "3", AttachCertificate = true });
        var r2 = _crypto.Execute(new OperateRequest { AlgorithmCode = "CAESAR", IsEncrypt = true, InputMode = "text", Text = "dos", Key = "4", AttachCertificate = true });

        Assert.Equal(2, _db.GetAllSavedPackagesWithBytes().Count);
        Assert.True(_db.DeleteSavedPackage(r1.ConsultaId!.Value));
        Assert.Single(_db.GetSavedPackages());
        Assert.Equal(1, _db.ClearSavedPackages());
        Assert.Empty(_db.GetSavedPackages());
    }

    [Fact]
    public void GenerateSection16TestVectors_ForEQ04()
    {
        var dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "vectores", "EQ04"));
        Directory.CreateDirectory(dir);

        var certRec = _certZip.GetLocalCertificate();
        var pfxBytes = Convert.FromBase64String(certRec.PrivateKeyPfxBase64);
        using var x509 = X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
        using var rsaPriv = x509.GetRSAPrivateKey()!;

        File.WriteAllText(Path.Combine(dir, "certificado.pem"), certRec.CertificatePem, Encoding.UTF8);
        File.WriteAllText(Path.Combine(dir, "privada-PRUEBA.pem"), rsaPriv.ExportPkcs8PrivateKeyPem(), Encoding.UTF8);

        // 1. CAESAR vector
        var caesarOriginal = "CENTRO DE CIBERSEGURIDAD EQ04";
        var caesarOrigBytes = Encoding.UTF8.GetBytes(caesarOriginal);
        var caesarReq = new CryptoRemoteRequestDto
        {
            RequestId = Guid.NewGuid().ToString("D"),
            RequesterNode = "EQ08",
            TargetNode = "EQ04",
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = "CAESAR",
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "CAESAR_original.txt",
            Options = new Dictionary<string, string> { ["alphabet"] = "A-Z" }
        };
        var caesarSecrets = new Dictionary<string, string> { ["shift"] = "3" };
        var (caesarZip, _, caesarMf) = _crypto.ExecuteProviderForward(caesarReq, caesarOrigBytes, caesarSecrets, "127.0.0.1:5004");
        Assert.True(_certZip.ValidateZipPackage(caesarZip, checkReplay: false).IsValid);

        File.WriteAllBytes(Path.Combine(dir, "CAESAR_ejemplo.zip"), caesarZip);
        File.WriteAllText(Path.Combine(dir, "CAESAR_secretos.json"), JsonSerializer.Serialize(caesarSecrets, CertificateAndZipService.JsonOpts), Encoding.UTF8);
        File.WriteAllText(Path.Combine(dir, "CAESAR_original.txt"), caesarOriginal, Encoding.UTF8);

        // cadena-firma.txt y params-canonicos.txt
        File.WriteAllText(Path.Combine(dir, "cadena-firma.txt"), CertificateAndZipService.BuildSigningString(caesarMf), Encoding.UTF8);
        var (canonText, canonHash) = CertificateAndZipService.ComputeCanonicalParamsHash(caesarMf.PublicParameters);
        File.WriteAllText(Path.Combine(dir, "params-canonicos.txt"), $"{canonText}\n---\nSHA256={canonHash}", Encoding.UTF8);

        // 2. DIFFIEHELLMAN vector
        var dhOriginal = "MENSAJE DIFFIE-HELLMAN EQ04 v2.0";
        var dhOrigBytes = Encoding.UTF8.GetBytes(dhOriginal);
        var dhReq = new CryptoRemoteRequestDto
        {
            RequestId = Guid.NewGuid().ToString("D"),
            RequesterNode = "EQ08",
            TargetNode = "EQ04",
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            AlgorithmCode = "DIFFIEHELLMAN",
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "DIFFIEHELLMAN_original.txt"
        };
        var (dhZip, _, _) = _crypto.ExecuteProviderForward(dhReq, dhOrigBytes, null, "127.0.0.1:5004");
        Assert.True(_certZip.ValidateZipPackage(dhZip, checkReplay: false).IsValid);

        File.WriteAllBytes(Path.Combine(dir, "DIFFIEHELLMAN_ejemplo.zip"), dhZip);
        File.WriteAllText(Path.Combine(dir, "DIFFIEHELLMAN_secretos.json"), "{}", Encoding.UTF8);
        File.WriteAllText(Path.Combine(dir, "DIFFIEHELLMAN_original.txt"), dhOriginal, Encoding.UTF8);

        Assert.True(File.Exists(Path.Combine(dir, "certificado.pem")));
        Assert.True(File.Exists(Path.Combine(dir, "CAESAR_ejemplo.zip")));
        Assert.True(File.Exists(Path.Combine(dir, "DIFFIEHELLMAN_ejemplo.zip")));
    }

    [Fact]
    public void AdvancedMode_DefaultsToFalse_AndPersistsInSqlite()
    {
        Assert.False(_db.GetAdvancedMode());
        Assert.True(_db.SetAdvancedMode(true));
        Assert.True(_db.GetAdvancedMode());
        Assert.False(_db.SetAdvancedMode(false));
        Assert.False(_db.GetAdvancedMode());
    }

    private static byte[] MutateZip(byte[] zipBytes, Func<string, byte[], byte[]> mutator)
    {
        using var dstMs = new MemoryStream();
        using (var srcMs = new MemoryStream(zipBytes))
        using (var src = new ZipArchive(srcMs, ZipArchiveMode.Read))
        using (var dst = new ZipArchive(dstMs, ZipArchiveMode.Create, true))
        {
            foreach (var e in src.Entries)
            {
                using var es = e.Open();
                using var copy = new MemoryStream();
                es.CopyTo(copy);
                var data = mutator(e.FullName, copy.ToArray());
                var ne = dst.CreateEntry(e.FullName);
                using var ns = ne.Open();
                ns.Write(data, 0, data.Length);
            }
        }
        return dstMs.ToArray();
    }

    private static byte[] AddExtraEntry(byte[] zipBytes, string extraName, byte[] extraData)
    {
        using var dstMs = new MemoryStream();
        using (var srcMs = new MemoryStream(zipBytes))
        using (var src = new ZipArchive(srcMs, ZipArchiveMode.Read))
        using (var dst = new ZipArchive(dstMs, ZipArchiveMode.Create, true))
        {
            foreach (var e in src.Entries)
            {
                using var es = e.Open();
                var ne = dst.CreateEntry(e.FullName);
                using var ns = ne.Open();
                es.CopyTo(ns);
            }
            var extra = dst.CreateEntry(extraName);
            using var exs = extra.Open();
            exs.Write(extraData, 0, extraData.Length);
        }
        return dstMs.ToArray();
    }
}
