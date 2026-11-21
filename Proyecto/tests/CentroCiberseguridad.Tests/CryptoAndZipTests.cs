using System.IO.Compression;
using System.Text;
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
        _dbFile = Path.Combine(Path.GetTempPath(), $"csec_test_{Guid.NewGuid():N}.db");
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
        const string sample = "Hola Centro de Ciberseguridad 2026";
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
        Assert.StartsWith($"NODO04_{code}_", enc.ZipFileName);
        Assert.Equal(16, enc.Cells.Length);
        Assert.NotEmpty(enc.Steps);

        if (code == "HASHSHA")
        {
            // Para HASHSHA, Descifrar verifica el hash esperado enviado en Key
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
            ? string.Join("\n", enc.OutputText!.Split('\n').Take(3)) // solo K=3 de N=5 shares
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
        // Deshabilita solo encriptación para AESGCM
        _db.UpdateAlgorithm("AESGCM", isVisible: true, canEncrypt: false, canDecrypt: true);

        Assert.Throws<UnauthorizedAccessException>(() => _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "AESGCM",
            IsEncrypt = true,
            InputMode = "text",
            Text = "hola"
        }));

        // Habilita encriptación pero deshabilita desencriptación
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

        // Ocultar Todos bloquea por completo
        _db.HideAllAlgorithms();
        var algos = _db.GetAlgorithms();
        Assert.Equal(21, algos.Count);
        Assert.All(algos, a => Assert.False(a.IsVisible));

        Assert.Throws<UnauthorizedAccessException>(() => _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = "CAESAR",
            IsEncrypt = true,
            InputMode = "text",
            Text = "hola"
        }));
    }

    [Fact]
    public void ZipPackage_ContainsThreeFilesAndDetectsTampering()
    {
        var encBytes = Encoding.UTF8.GetBytes("datos-cifrados-de-prueba");
        var (zipBytes, zipName, manifest) = _certZip.CreateSignedZipPackage(
            encBytes, "AESGCM", "AES-256-GCM", "text", "secreto.txt", 20);

        Assert.EndsWith(".zip", zipName);
        Assert.Equal("AESGCM", manifest.AlgorithmCode);

        using (var ms = new MemoryStream(zipBytes))
        using (var ar = new ZipArchive(ms, ZipArchiveMode.Read))
        {
            Assert.NotNull(ar.GetEntry("datos.enc"));
            Assert.NotNull(ar.GetEntry("certificado.pem"));
            Assert.NotNull(ar.GetEntry("manifest.json"));
            Assert.Equal(3, ar.Entries.Count);
        }

        var valid = _certZip.ValidateZipPackage(zipBytes);
        Assert.True(valid.IsValid);
        Assert.Equal(202, valid.HttpStatusCode);

        // Alterar 1 byte de datos.enc en el ZIP
        using var tamperedMs = new MemoryStream();
        using (var srcMs = new MemoryStream(zipBytes))
        using (var srcZip = new ZipArchive(srcMs, ZipArchiveMode.Read))
        using (var dstZip = new ZipArchive(tamperedMs, ZipArchiveMode.Create, true))
        {
            foreach (var entry in srcZip.Entries)
            {
                using var es = entry.Open();
                using var copyMs = new MemoryStream();
                es.CopyTo(copyMs);
                var data = copyMs.ToArray();
                if (entry.FullName == "datos.enc") data[0] ^= 0x01;
                var newEntry = dstZip.CreateEntry(entry.FullName);
                using var ns = newEntry.Open();
                ns.Write(data, 0, data.Length);
            }
        }

        var invalid = _certZip.ValidateZipPackage(tamperedMs.ToArray());
        Assert.False(invalid.IsValid);
        Assert.Equal(422, invalid.HttpStatusCode);
    }

    [Fact]
    public void IncomingRequests_AcceptAddsToConsultas_RejectDoesNot()
    {
        var (zipBytes, zipName, mf) = _certZip.CreateSignedZipPackage(
            "abc"u8.ToArray(), "CHACHA20", "ChaCha20-Poly1305", "text", "doc.txt", 3);

        var id1 = _db.AddIncomingRequest(new IncomingRequestRecord
        {
            PacketId = mf.PacketId,
            SourceIp = "192.168.1.30:5000",
            ZipFileName = zipName,
            AlgorithmCode = mf.AlgorithmCode,
            AlgorithmName = mf.Algorithm,
            SignatureValid = true,
            Status = "Pendiente",
            EncryptedSha256 = mf.EncryptedSha256,
            ReceivedAt = "2026-11-16 21:55",
            ZipBytes = zipBytes
        });

        var id2 = _db.AddIncomingRequest(new IncomingRequestRecord
        {
            PacketId = Guid.NewGuid().ToString(),
            SourceIp = "192.168.1.31:5000",
            ZipFileName = "rechazado.zip",
            AlgorithmCode = "RSA",
            AlgorithmName = "RSA",
            SignatureValid = true,
            Status = "Pendiente",
            EncryptedSha256 = mf.EncryptedSha256,
            ReceivedAt = "2026-11-16 21:56",
            ZipBytes = zipBytes
        });

        var saved = _db.AcceptIncomingRequest(id1);
        Assert.NotNull(saved);
        Assert.Equal("Recibido", saved!.Origin);

        var rejected = _db.RejectIncomingRequest(id2);
        Assert.True(rejected);

        var consultas = _db.GetSavedPackages();
        Assert.Single(consultas);
        Assert.Equal(zipName, consultas[0].ZipFileName);
        Assert.Equal("Recibido", consultas[0].Origin);

        var reqs = _db.GetIncomingRequests();
        Assert.Equal("Aceptada", reqs.First(r => r.Id == id1).Status);
        Assert.Equal("Rechazada", reqs.First(r => r.Id == id2).Status);
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

    [Theory]
    [InlineData("CHACHA20", "clave-secreta-personal", false)]
    [InlineData("CAESAR", "5", true)]
    public void UnpackZipFromConsultas_ReadsManifestAndDecryptsDirectly(string code, string key, bool isTextNative)
    {
        const string secret = "Dato confidencial para Consultas";
        var enc = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = code,
            IsEncrypt = true,
            InputMode = "text",
            Text = secret,
            Key = key,
            AttachCertificate = true
        });

        Assert.NotNull(enc.ConsultaId);
        var saved = _db.GetSavedPackageById(enc.ConsultaId!.Value);
        Assert.NotNull(saved);

        var val = _certZip.ValidateZipPackage(saved!.ZipBytes);
        Assert.True(val.IsValid);
        Assert.Equal(code, val.Manifest!.AlgorithmCode);

        var extractedText = isTextNative
            ? Encoding.UTF8.GetString(val.EncryptedBytes)
            : Convert.ToBase64String(val.EncryptedBytes);
        var dec = _crypto.Execute(new OperateRequest
        {
            AlgorithmCode = val.Manifest.AlgorithmCode,
            IsEncrypt = false,
            InputMode = val.Manifest.PayloadMode,
            Text = extractedText,
            Key = key,
            AttachCertificate = false
        });

        Assert.Equal(secret, dec.OutputText);
    }

    [Fact]
    public void Consultas_DeleteSingle_ClearAll_AndGetAllWithBytes_Works()
    {
        var r1 = _crypto.Execute(new OperateRequest { AlgorithmCode = "CAESAR", IsEncrypt = true, InputMode = "text", Text = "uno", Key = "3", AttachCertificate = true });
        var r2 = _crypto.Execute(new OperateRequest { AlgorithmCode = "CAESAR", IsEncrypt = true, InputMode = "text", Text = "dos", Key = "4", AttachCertificate = true });

        Assert.Equal(2, _db.GetAllSavedPackagesWithBytes().Count);

        Assert.True(_db.DeleteSavedPackage(r1.ConsultaId!.Value));
        Assert.Single(_db.GetSavedPackages());
        Assert.Equal(r2.ConsultaId, _db.GetSavedPackages()[0].Id);

        Assert.Equal(1, _db.ClearSavedPackages());
        Assert.Empty(_db.GetSavedPackages());
    }
}
