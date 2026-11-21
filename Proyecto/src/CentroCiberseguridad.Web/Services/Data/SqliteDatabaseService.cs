using CentroCiberseguridad.Web.Models;
using Microsoft.Data.Sqlite;

namespace CentroCiberseguridad.Web.Services.Data;

public sealed class SqliteDatabaseService
{
    private readonly string _connectionString;
    private readonly object _writeLock = new();

    public static readonly IReadOnlyList<AlgorithmConfig> DefaultAlgorithms = new List<AlgorithmConfig>
    {
        new() { Code = "AESGCM", Name = "AES-256-GCM", Category = "Simétrico", DefaultKey = "clave-aes-256-segura" },
        new() { Code = "DES", Name = "DES (56-bit)", Category = "Simétrico", DefaultKey = "claveDES" },
        new() { Code = "TRIPLEDES", Name = "Triple DES / 3DES-96", Category = "Simétrico", DefaultKey = "clave-3des-96-ede" },
        new() { Code = "CHACHA20", Name = "ChaCha20-Poly1305", Category = "Simétrico", DefaultKey = "chacha20-llave-32bytes" },
        new() { Code = "RSA", Name = "RSA (OAEP / Modular)", Category = "Asimétrico", DefaultKey = "p=257,q=263,e=3" },
        new() { Code = "ECC", Name = "ECC (ECDH / ECIES)", Category = "Asimétrico", DefaultKey = "ecc-p256-secp256r1" },
        new() { Code = "DIFFIEHELLMAN", Name = "Diffie-Hellman (g^a mod p)", Category = "Acuerdo", DefaultKey = "p=467,g=2,a=15,b=27" },
        new() { Code = "CAESAR", Name = "Cifrado César", Category = "Clásico", DefaultKey = "3" },
        new() { Code = "VIGENERE", Name = "Cifrado Vigenère", Category = "Clásico", DefaultKey = "SOL" },
        new() { Code = "XORASM", Name = "XOR Ensamblador (WREG/ROL)", Category = "Bajo Nivel", DefaultKey = "0x5A,ROL=1" },
        new() { Code = "LSBSTEGO", Name = "Esteganografía LSB", Category = "Estego", DefaultKey = "1-bit-RGB" },
        new() { Code = "EUCLIDESAFFINE", Name = "Euclides Extendido (Afín)", Category = "Matemático", DefaultKey = "a=5,b=11" },
        new() { Code = "MILLERRABIN", Name = "Miller–Rabin (Primos)", Category = "Matemático", DefaultKey = "n=1009,rondas=5" },
        new() { Code = "FISHERYATES", Name = "Permutación Fisher–Yates", Category = "Transposición", DefaultKey = "semilla-2026" },
        new() { Code = "HASHSHA", Name = "Hash SHA-256", Category = "Integridad", DefaultKey = "sha256" },
        new() { Code = "HMACSHA256", Name = "HMAC-SHA256", Category = "Autenticación", DefaultKey = "secreto-hmac" },
        new() { Code = "DIGITALSIG", Name = "Firma Digital (PSS/ECDSA)", Category = "Autenticidad", DefaultKey = "NODO-04-PRIV" },
        new() { Code = "QUANTUMPQC", Name = "Cuántica BB84 + PQC (LWE)", Category = "Poscuántico", DefaultKey = "bb84-eve=0" },
        new() { Code = "DFTSPECTRAL", Name = "Transformada DFT / IDFT", Category = "Señales", DefaultKey = "fase-42" },
        new() { Code = "LAGRANGESHAMIR", Name = "Lagrange (Shamir GF256)", Category = "Álgebra", DefaultKey = "N=5,K=3" },
        new() { Code = "LORENZSZ40", Name = "Máquina Lorenz (SZ40)", Category = "Flujo", DefaultKey = "chi=13,psi=29" }
    };

    public SqliteDatabaseService(string databasePath = "ciberseguridad.db")
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString();

        InitializeSchemaAndSeed();
    }

    private SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private void InitializeSchemaAndSeed()
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                PRAGMA journal_mode = WAL;

                CREATE TABLE IF NOT EXISTS AlgorithmConfigs (
                    Code TEXT PRIMARY KEY,
                    Name TEXT NOT NULL,
                    Category TEXT NOT NULL,
                    DefaultKey TEXT NOT NULL,
                    IsVisible INTEGER NOT NULL DEFAULT 1,
                    CanEncrypt INTEGER NOT NULL DEFAULT 1,
                    CanDecrypt INTEGER NOT NULL DEFAULT 1,
                    UpdatedAtUtc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS DigitalCertificates (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    SubjectName TEXT NOT NULL,
                    ThumbprintSha256 TEXT NOT NULL,
                    SerialNumber TEXT NOT NULL,
                    IsLocalNode INTEGER NOT NULL DEFAULT 1,
                    CertificatePem TEXT NOT NULL,
                    PrivateKeyPfxBase64 TEXT NOT NULL,
                    NotBeforeUtc TEXT NOT NULL,
                    NotAfterUtc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS SavedPackages (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ZipFileName TEXT NOT NULL,
                    Origin TEXT NOT NULL,
                    SourceIp TEXT NOT NULL,
                    AlgorithmCode TEXT NOT NULL,
                    AlgorithmName TEXT NOT NULL,
                    EncryptedSha256 TEXT NOT NULL,
                    CreatedAt TEXT NOT NULL,
                    ZipBytes BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS IncomingRequests (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    PacketId TEXT NOT NULL,
                    SourceIp TEXT NOT NULL,
                    ZipFileName TEXT NOT NULL,
                    AlgorithmCode TEXT NOT NULL,
                    AlgorithmName TEXT NOT NULL,
                    SignatureValid INTEGER NOT NULL,
                    Status TEXT NOT NULL,
                    EncryptedSha256 TEXT NOT NULL,
                    ReceivedAt TEXT NOT NULL,
                    ZipBytes BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS CryptoOperationsLog (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AlgorithmCode TEXT NOT NULL,
                    OperationType TEXT NOT NULL,
                    InputKind TEXT NOT NULL,
                    InputSha256 TEXT NOT NULL,
                    OutputSha256 TEXT NOT NULL,
                    DurationMs INTEGER NOT NULL,
                    CreatedAtUtc TEXT NOT NULL
                );
                """;
            cmd.ExecuteNonQuery();

            var now = DateTime.UtcNow.ToString("O");
            foreach (var algo in DefaultAlgorithms)
            {
                using var ins = conn.CreateCommand();
                ins.CommandText = """
                    INSERT OR IGNORE INTO AlgorithmConfigs (Code, Name, Category, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc)
                    VALUES ($code, $name, $cat, $key, 1, 1, 1, $now);
                    """;
                ins.Parameters.AddWithValue("$code", algo.Code);
                ins.Parameters.AddWithValue("$name", algo.Name);
                ins.Parameters.AddWithValue("$cat", algo.Category);
                ins.Parameters.AddWithValue("$key", algo.DefaultKey);
                ins.Parameters.AddWithValue("$now", now);
                ins.ExecuteNonQuery();
            }
        }
    }

    public List<AlgorithmConfig> GetAlgorithms()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Code, Name, Category, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc FROM AlgorithmConfigs ORDER BY rowid ASC;";
        using var reader = cmd.ExecuteReader();
        var list = new List<AlgorithmConfig>();
        while (reader.Read())
        {
            list.Add(ReadAlgorithm(reader));
        }
        return list;
    }

    public AlgorithmConfig? GetAlgorithm(string code)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Code, Name, Category, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc FROM AlgorithmConfigs WHERE Code = $code;";
        cmd.Parameters.AddWithValue("$code", code.ToUpperInvariant());
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadAlgorithm(reader) : null;
    }

    public AlgorithmConfig? UpdateAlgorithm(string code, bool isVisible, bool canEncrypt, bool canDecrypt)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE AlgorithmConfigs
                SET IsVisible = $vis, CanEncrypt = $enc, CanDecrypt = $dec, UpdatedAtUtc = $now
                WHERE Code = $code;
                """;
            cmd.Parameters.AddWithValue("$vis", isVisible ? 1 : 0);
            cmd.Parameters.AddWithValue("$enc", canEncrypt ? 1 : 0);
            cmd.Parameters.AddWithValue("$dec", canDecrypt ? 1 : 0);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$code", code.ToUpperInvariant());
            if (cmd.ExecuteNonQuery() == 0) return null;
        }
        return GetAlgorithm(code);
    }

    public void HideAllAlgorithms()
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE AlgorithmConfigs SET IsVisible = 0, CanEncrypt = 0, CanDecrypt = 0, UpdatedAtUtc = $now;";
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public DigitalCertificateRecord GetOrCreateLocalCertificate(Func<DigitalCertificateRecord> generator)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var sel = conn.CreateCommand();
            sel.CommandText = "SELECT Id, SubjectName, ThumbprintSha256, SerialNumber, IsLocalNode, CertificatePem, PrivateKeyPfxBase64, NotBeforeUtc, NotAfterUtc FROM DigitalCertificates WHERE IsLocalNode = 1 AND SubjectName LIKE '%NODO-04%' ORDER BY Id DESC LIMIT 1;";
            using (var r = sel.ExecuteReader())
            {
                if (r.Read())
                {
                    return new DigitalCertificateRecord
                    {
                        Id = r.GetInt32(0),
                        SubjectName = r.GetString(1),
                        ThumbprintSha256 = r.GetString(2),
                        SerialNumber = r.GetString(3),
                        IsLocalNode = r.GetInt32(4) == 1,
                        CertificatePem = r.GetString(5),
                        PrivateKeyPfxBase64 = r.GetString(6),
                        NotBeforeUtc = r.GetString(7),
                        NotAfterUtc = r.GetString(8)
                    };
                }
            }

            var created = generator();
            using var ins = conn.CreateCommand();
            ins.CommandText = """
                INSERT INTO DigitalCertificates (SubjectName, ThumbprintSha256, SerialNumber, IsLocalNode, CertificatePem, PrivateKeyPfxBase64, NotBeforeUtc, NotAfterUtc)
                VALUES ($sub, $thumb, $serial, 1, $pem, $pfx, $nb, $na);
                SELECT last_insert_rowid();
                """;
            ins.Parameters.AddWithValue("$sub", created.SubjectName);
            ins.Parameters.AddWithValue("$thumb", created.ThumbprintSha256);
            ins.Parameters.AddWithValue("$serial", created.SerialNumber);
            ins.Parameters.AddWithValue("$pem", created.CertificatePem);
            ins.Parameters.AddWithValue("$pfx", created.PrivateKeyPfxBase64);
            ins.Parameters.AddWithValue("$nb", created.NotBeforeUtc);
            ins.Parameters.AddWithValue("$na", created.NotAfterUtc);
            created.Id = Convert.ToInt32(ins.ExecuteScalar());
            return created;
        }
    }

    public long AddSavedPackage(SavedPackageRecord rec)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO SavedPackages (ZipFileName, Origin, SourceIp, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes)
                VALUES ($file, $origin, $ip, $code, $name, $sha, $created, $bytes);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$file", rec.ZipFileName);
            cmd.Parameters.AddWithValue("$origin", rec.Origin);
            cmd.Parameters.AddWithValue("$ip", rec.SourceIp);
            cmd.Parameters.AddWithValue("$code", rec.AlgorithmCode);
            cmd.Parameters.AddWithValue("$name", rec.AlgorithmName);
            cmd.Parameters.AddWithValue("$sha", rec.EncryptedSha256);
            cmd.Parameters.AddWithValue("$created", rec.CreatedAt);
            cmd.Parameters.AddWithValue("$bytes", rec.ZipBytes);
            rec.Id = Convert.ToInt64(cmd.ExecuteScalar());
            return rec.Id;
        }
    }

    public List<SavedPackageRecord> GetSavedPackages()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceIp, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt FROM SavedPackages ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<SavedPackageRecord>();
        while (r.Read())
        {
            list.Add(new SavedPackageRecord
            {
                Id = r.GetInt64(0),
                ZipFileName = r.GetString(1),
                Origin = r.GetString(2),
                SourceIp = r.GetString(3),
                AlgorithmCode = r.GetString(4),
                AlgorithmName = r.GetString(5),
                EncryptedSha256 = r.GetString(6),
                CreatedAt = r.GetString(7)
            });
        }
        return list;
    }

    public SavedPackageRecord? GetSavedPackageById(long id)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceIp, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes FROM SavedPackages WHERE Id = $id;";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new SavedPackageRecord
        {
            Id = r.GetInt64(0),
            ZipFileName = r.GetString(1),
            Origin = r.GetString(2),
            SourceIp = r.GetString(3),
            AlgorithmCode = r.GetString(4),
            AlgorithmName = r.GetString(5),
            EncryptedSha256 = r.GetString(6),
            CreatedAt = r.GetString(7),
            ZipBytes = (byte[])r["ZipBytes"]
        };
    }

    public List<SavedPackageRecord> GetAllSavedPackagesWithBytes()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceIp, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes FROM SavedPackages ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<SavedPackageRecord>();
        while (r.Read())
        {
            list.Add(new SavedPackageRecord
            {
                Id = r.GetInt64(0),
                ZipFileName = r.GetString(1),
                Origin = r.GetString(2),
                SourceIp = r.GetString(3),
                AlgorithmCode = r.GetString(4),
                AlgorithmName = r.GetString(5),
                EncryptedSha256 = r.GetString(6),
                CreatedAt = r.GetString(7),
                ZipBytes = (byte[])r["ZipBytes"]
            });
        }
        return list;
    }

    public bool DeleteSavedPackage(long id)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM SavedPackages WHERE Id = $id;";
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public int ClearSavedPackages()
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM SavedPackages;";
            return cmd.ExecuteNonQuery();
        }
    }

    public long AddIncomingRequest(IncomingRequestRecord req)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO IncomingRequests (PacketId, SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, SignatureValid, Status, EncryptedSha256, ReceivedAt, ZipBytes)
                VALUES ($pid, $ip, $file, $code, $name, $sig, $status, $sha, $rec, $bytes);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$pid", req.PacketId);
            cmd.Parameters.AddWithValue("$ip", req.SourceIp);
            cmd.Parameters.AddWithValue("$file", req.ZipFileName);
            cmd.Parameters.AddWithValue("$code", req.AlgorithmCode);
            cmd.Parameters.AddWithValue("$name", req.AlgorithmName);
            cmd.Parameters.AddWithValue("$sig", req.SignatureValid ? 1 : 0);
            cmd.Parameters.AddWithValue("$status", req.Status);
            cmd.Parameters.AddWithValue("$sha", req.EncryptedSha256);
            cmd.Parameters.AddWithValue("$rec", req.ReceivedAt);
            cmd.Parameters.AddWithValue("$bytes", req.ZipBytes);
            req.Id = Convert.ToInt64(cmd.ExecuteScalar());
            return req.Id;
        }
    }

    public List<IncomingRequestRecord> GetIncomingRequests()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, PacketId, SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, SignatureValid, Status, EncryptedSha256, ReceivedAt FROM IncomingRequests ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<IncomingRequestRecord>();
        while (r.Read())
        {
            list.Add(new IncomingRequestRecord
            {
                Id = r.GetInt64(0),
                PacketId = r.GetString(1),
                SourceIp = r.GetString(2),
                ZipFileName = r.GetString(3),
                AlgorithmCode = r.GetString(4),
                AlgorithmName = r.GetString(5),
                SignatureValid = r.GetInt32(6) == 1,
                Status = r.GetString(7),
                EncryptedSha256 = r.GetString(8),
                ReceivedAt = r.GetString(9)
            });
        }
        return list;
    }

    public SavedPackageRecord? AcceptIncomingRequest(long requestId)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var tx = conn.BeginTransaction();

            using var sel = conn.CreateCommand();
            sel.Transaction = tx;
            sel.CommandText = "SELECT SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, EncryptedSha256, Status, ZipBytes FROM IncomingRequests WHERE Id = $id;";
            sel.Parameters.AddWithValue("$id", requestId);
            using var r = sel.ExecuteReader();
            if (!r.Read()) return null;

            var status = r.GetString(5);
            var sourceIp = r.GetString(0);
            var zipFileName = r.GetString(1);
            var algoCode = r.GetString(2);
            var algoName = r.GetString(3);
            var sha = r.GetString(4);
            var zipBytes = (byte[])r["ZipBytes"];
            r.Close();

            if (status != "Pendiente") return null;

            using var upd = conn.CreateCommand();
            upd.Transaction = tx;
            upd.CommandText = "UPDATE IncomingRequests SET Status = 'Aceptada' WHERE Id = $id;";
            upd.Parameters.AddWithValue("$id", requestId);
            upd.ExecuteNonQuery();

            var createdAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            using var ins = conn.CreateCommand();
            ins.Transaction = tx;
            ins.CommandText = """
                INSERT INTO SavedPackages (ZipFileName, Origin, SourceIp, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes)
                VALUES ($file, 'Recibido', $ip, $code, $name, $sha, $created, $bytes);
                SELECT last_insert_rowid();
                """;
            ins.Parameters.AddWithValue("$file", zipFileName);
            ins.Parameters.AddWithValue("$ip", sourceIp);
            ins.Parameters.AddWithValue("$code", algoCode);
            ins.Parameters.AddWithValue("$name", algoName);
            ins.Parameters.AddWithValue("$sha", sha);
            ins.Parameters.AddWithValue("$created", createdAt);
            ins.Parameters.AddWithValue("$bytes", zipBytes);
            var savedId = Convert.ToInt64(ins.ExecuteScalar());

            tx.Commit();

            return new SavedPackageRecord
            {
                Id = savedId,
                ZipFileName = zipFileName,
                Origin = "Recibido",
                SourceIp = sourceIp,
                AlgorithmCode = algoCode,
                AlgorithmName = algoName,
                EncryptedSha256 = sha,
                CreatedAt = createdAt,
                ZipBytes = zipBytes
            };
        }
    }

    public bool RejectIncomingRequest(long requestId)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE IncomingRequests SET Status = 'Rechazada' WHERE Id = $id AND Status = 'Pendiente';";
            cmd.Parameters.AddWithValue("$id", requestId);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public void LogCryptoOperation(string code, string opType, string inputKind, string inSha, string outSha, long durationMs)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO CryptoOperationsLog (AlgorithmCode, OperationType, InputKind, InputSha256, OutputSha256, DurationMs, CreatedAtUtc)
                VALUES ($code, $op, $kind, $inSha, $outSha, $ms, $now);
                """;
            cmd.Parameters.AddWithValue("$code", code);
            cmd.Parameters.AddWithValue("$op", opType);
            cmd.Parameters.AddWithValue("$kind", inputKind);
            cmd.Parameters.AddWithValue("$inSha", inSha);
            cmd.Parameters.AddWithValue("$outSha", outSha);
            cmd.Parameters.AddWithValue("$ms", durationMs);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    private static AlgorithmConfig ReadAlgorithm(SqliteDataReader r) => new()
    {
        Code = r.GetString(0),
        Name = r.GetString(1),
        Category = r.GetString(2),
        DefaultKey = r.GetString(3),
        IsVisible = r.GetInt32(4) == 1,
        CanEncrypt = r.GetInt32(5) == 1,
        CanDecrypt = r.GetInt32(6) == 1,
        UpdatedAtUtc = r.GetString(7)
    };
}
