using System.Text.Json;
using CentroCiberseguridad.Web.Models;
using Microsoft.Data.Sqlite;

namespace CentroCiberseguridad.Web.Services.Data;

public sealed class SqliteDatabaseService
{
    private readonly string _connectionString;
    private readonly object _writeLock = new();

    public const int LocalTeamNumber = 4;
    public const string LocalNodeId = "EQ04";
    public const int LocalHttpPort = 5004;
    public const int UdpDiscoveryPort = 5099;

    public static readonly IReadOnlyList<AlgorithmConfig> DefaultAlgorithms = new List<AlgorithmConfig>
    {
        new() { AlgorithmId = 1,  Code = "AESGCM",         Name = "AES-256-GCM / AES-128-GCM",        Category = "Simétrico por bloques", OwnerTeam = 1, OwnerNode = "EQ01", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "clave-aes-256-segura" },
        new() { AlgorithmId = 2,  Code = "DES",            Name = "DES 56-bit",                       Category = "Simétrico legado",      OwnerTeam = 1, OwnerNode = "EQ01", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "claveDES" },
        new() { AlgorithmId = 3,  Code = "TRIPLEDES",      Name = "Triple DES / 3DES",                Category = "Simétrico legado",      OwnerTeam = 2, OwnerNode = "EQ02", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "clave-3des-96-ede" },
        new() { AlgorithmId = 4,  Code = "CHACHA20",       Name = "ChaCha20-Poly1305",                Category = "Simétrico de flujo",    OwnerTeam = 2, OwnerNode = "EQ02", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "chacha20-llave-32bytes" },
        new() { AlgorithmId = 5,  Code = "RSA",            Name = "RSA-OAEP / RSA-PSS",               Category = "Asimétrico",            OwnerTeam = 3, OwnerNode = "EQ03", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "keyId",            DefaultKey = "p=257,q=263,e=3" },
        new() { AlgorithmId = 6,  Code = "ECC",            Name = "ECDH / ECIES / ECDSA",             Category = "Asimétrico (ECC)",      OwnerTeam = 3, OwnerNode = "EQ03", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "keyId",            DefaultKey = "ecc-p256-secp256r1" },
        new() { AlgorithmId = 7,  Code = "DIFFIEHELLMAN",  Name = "Diffie-Hellman",                   Category = "Acuerdo de claves",     OwnerTeam = 4, OwnerNode = "EQ04", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "keyId",            DefaultKey = "p=467,g=2,a=15,b=27" },
        new() { AlgorithmId = 8,  Code = "CAESAR",         Name = "Cifrado César",                    Category = "Clásico",               OwnerTeam = 4, OwnerNode = "EQ04", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "3" },
        new() { AlgorithmId = 9,  Code = "VIGENERE",       Name = "Cifrado Vigenère",                 Category = "Clásico polialfabético",OwnerTeam = 5, OwnerNode = "EQ05", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "SOL" },
        new() { AlgorithmId = 10, Code = "XORASM",         Name = "XOR en registro (WREG/ROL/ROR)",   Category = "Bajo nivel",            OwnerTeam = 5, OwnerNode = "EQ05", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "0x5A,ROL=1" },
        new() { AlgorithmId = 11, Code = "LSBSTEGO",       Name = "Esteganografía LSB en PNG/BMP",    Category = "Esteganografía",        OwnerTeam = 6, OwnerNode = "EQ06", ForwardName = "ocultar",     InverseName = "extraer",    KeyType = "Secreta opcional", DefaultKey = "1-bit-RGB" },
        new() { AlgorithmId = 12, Code = "EUCLIDESAFFINE", Name = "Euclides extendido / Afín",        Category = "Teoría de números",     OwnerTeam = 6, OwnerNode = "EQ06", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "a=5,b=11" },
        new() { AlgorithmId = 13, Code = "MILLERRABIN",    Name = "Miller–Rabin + cifrado modular",   Category = "Primalidad",            OwnerTeam = 7, OwnerNode = "EQ07", ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "keyId",            DefaultKey = "n=1009,rondas=5" },
        new() { AlgorithmId = 14, Code = "FISHERYATES",    Name = "Permutación Fisher–Yates",         Category = "Transposición",         OwnerTeam = 7, OwnerNode = "EQ07", ForwardName = "permutar",    InverseName = "restaurar",  KeyType = "Secreta",          DefaultKey = "semilla-2026" },
        new() { AlgorithmId = 15, Code = "HASHSHA",        Name = "SHA-256 / SHA-512 / SHA-3",        Category = "Integridad",            OwnerTeam = 8, OwnerNode = "EQ08", ForwardName = "calcular hash",InverseName = "verificar", KeyType = "Ninguna",          DefaultKey = "sha256" },
        new() { AlgorithmId = 16, Code = "HMACSHA256",     Name = "HMAC-SHA256 / HMAC-SHA512",        Category = "Autenticación",         OwnerTeam = 8, OwnerNode = "EQ08", ForwardName = "calcular MAC",InverseName = "verificar",  KeyType = "Secreta",          DefaultKey = "secreto-hmac" },
        new() { AlgorithmId = 17, Code = "DIGITALSIG",     Name = "Firma digital RSA-PSS / ECDSA",    Category = "Autenticidad",          OwnerTeam = null, OwnerNode = null,  ForwardName = "firmar",      InverseName = "verificar",  KeyType = "keyId",            DefaultKey = "EQ04-PRIV" },
        new() { AlgorithmId = 18, Code = "QUANTUMPQC",     Name = "QKD BB84 + PQC (ML-KEM / LWE)",    Category = "Poscuántica",           OwnerTeam = null, OwnerNode = null,  ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "keyId",            DefaultKey = "bb84-eve=0" },
        new() { AlgorithmId = 19, Code = "DFTSPECTRAL",    Name = "Transformada discreta de Fourier", Category = "Señales",               OwnerTeam = null, OwnerNode = null,  ForwardName = "transformar", InverseName = "invertir",   KeyType = "Secreta opcional", DefaultKey = "fase-42" },
        new() { AlgorithmId = 20, Code = "LAGRANGESHAMIR", Name = "Shamir en GF(256)",                Category = "Umbral",                OwnerTeam = null, OwnerNode = null,  ForwardName = "dividir",     InverseName = "reconstruir",KeyType = "Ninguna",          DefaultKey = "N=5,K=3" },
        new() { AlgorithmId = 21, Code = "LORENZSZ40",     Name = "Lorenz SZ40/42",                   Category = "Flujo electromecánico", OwnerTeam = null, OwnerNode = null,  ForwardName = "cifrar",      InverseName = "descifrar",  KeyType = "Secreta",          DefaultKey = "chi=13,psi=29" }
    };

    public static readonly string[] OwnedAlgorithmCodes = { "DIFFIEHELLMAN", "CAESAR" };

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
                    AlgorithmId INTEGER NOT NULL DEFAULT 0,
                    Name TEXT NOT NULL,
                    Category TEXT NOT NULL,
                    OwnerTeam INTEGER NULL,
                    OwnerNode TEXT NULL,
                    ForwardName TEXT NOT NULL DEFAULT 'cifrar',
                    InverseName TEXT NOT NULL DEFAULT 'descifrar',
                    KeyType TEXT NOT NULL DEFAULT 'Secreta',
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
                    SourceNode TEXT NOT NULL DEFAULT 'EQ04',
                    ProducerNode TEXT NOT NULL DEFAULT 'EQ04',
                    SourceIp TEXT NOT NULL,
                    PacketType TEXT NOT NULL DEFAULT 'package',
                    AlgorithmCode TEXT NOT NULL,
                    AlgorithmName TEXT NOT NULL,
                    EncryptedSha256 TEXT NOT NULL,
                    CreatedAt TEXT NOT NULL,
                    ZipBytes BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS IncomingRequests (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    PacketId TEXT NOT NULL,
                    SourceNode TEXT NOT NULL DEFAULT 'EQ00',
                    SourceIp TEXT NOT NULL,
                    ZipFileName TEXT NOT NULL,
                    AlgorithmCode TEXT NOT NULL,
                    AlgorithmName TEXT NOT NULL,
                    OperationName TEXT NOT NULL DEFAULT 'cifrar',
                    SignatureValid INTEGER NOT NULL,
                    TrustStatus TEXT NOT NULL DEFAULT 'Firma OK',
                    Status TEXT NOT NULL,
                    EncryptedSha256 TEXT NOT NULL,
                    ReceivedAt TEXT NOT NULL,
                    ZipBytes BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS DirectoryNodes (
                    NodeId TEXT PRIMARY KEY,
                    TeamNumber INTEGER NOT NULL,
                    Ip TEXT NOT NULL,
                    HttpPort INTEGER NOT NULL,
                    HttpsPort INTEGER NULL,
                    CertificatePem TEXT NOT NULL,
                    AnnouncedThumbprintSha256 TEXT NOT NULL,
                    PinnedThumbprintSha256 TEXT NULL,
                    AlgorithmsJson TEXT NOT NULL DEFAULT '[]',
                    Source TEXT NOT NULL DEFAULT 'manual',
                    Status TEXT NOT NULL DEFAULT 'online',
                    LastSeenUtc TEXT NOT NULL,
                    TrustAlert INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS AsymmetricKeys (
                    KeyId TEXT PRIMARY KEY,
                    AlgorithmCode TEXT NOT NULL,
                    OwnerNode TEXT NOT NULL,
                    PublicParamsJson TEXT NOT NULL,
                    PrivateParamsJson TEXT NOT NULL,
                    AllowedNodes TEXT NULL,
                    CreatedAtUtc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS SeenIds (
                    Id TEXT PRIMARY KEY,
                    Kind TEXT NOT NULL,
                    SeenAtUtc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS AsyncJobs (
                    JobId TEXT PRIMARY KEY,
                    RequesterNode TEXT NOT NULL,
                    State TEXT NOT NULL,
                    ProgressPercent INTEGER NOT NULL DEFAULT 0,
                    ErrorJson TEXT NULL,
                    ResultZipBytes BLOB NULL,
                    ResultFileName TEXT NULL,
                    CreatedAtUtc TEXT NOT NULL
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

                CREATE TABLE IF NOT EXISTS AppSettings (
                    Key TEXT PRIMARY KEY,
                    Value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO AppSettings (Key, Value) VALUES ('AdvancedMode', '0');
                """;
            cmd.ExecuteNonQuery();

            // Migración suave si existía una BD v1.0 previa
            EnsureColumn(conn, "AlgorithmConfigs", "AlgorithmId", "INTEGER NOT NULL DEFAULT 0");
            EnsureColumn(conn, "AlgorithmConfigs", "OwnerTeam", "INTEGER NULL");
            EnsureColumn(conn, "AlgorithmConfigs", "OwnerNode", "TEXT NULL");
            EnsureColumn(conn, "AlgorithmConfigs", "ForwardName", "TEXT NOT NULL DEFAULT 'cifrar'");
            EnsureColumn(conn, "AlgorithmConfigs", "InverseName", "TEXT NOT NULL DEFAULT 'descifrar'");
            EnsureColumn(conn, "AlgorithmConfigs", "KeyType", "TEXT NOT NULL DEFAULT 'Secreta'");

            EnsureColumn(conn, "SavedPackages", "SourceNode", "TEXT NOT NULL DEFAULT 'EQ04'");
            EnsureColumn(conn, "SavedPackages", "ProducerNode", "TEXT NOT NULL DEFAULT 'EQ04'");
            EnsureColumn(conn, "SavedPackages", "PacketType", "TEXT NOT NULL DEFAULT 'package'");

            EnsureColumn(conn, "IncomingRequests", "SourceNode", "TEXT NOT NULL DEFAULT 'EQ00'");
            EnsureColumn(conn, "IncomingRequests", "OperationName", "TEXT NOT NULL DEFAULT 'cifrar'");
            EnsureColumn(conn, "IncomingRequests", "TrustStatus", "TEXT NOT NULL DEFAULT 'Firma OK'");

            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            foreach (var algo in DefaultAlgorithms)
            {
                using var ins = conn.CreateCommand();
                ins.CommandText = """
                    INSERT INTO AlgorithmConfigs (Code, AlgorithmId, Name, Category, OwnerTeam, OwnerNode, ForwardName, InverseName, KeyType, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc)
                    VALUES ($code, $aid, $name, $cat, $ot, $on, $fn, $in, $kt, $key, 1, 1, 1, $now)
                    ON CONFLICT(Code) DO UPDATE SET
                        AlgorithmId = excluded.AlgorithmId,
                        Name = excluded.Name,
                        Category = excluded.Category,
                        OwnerTeam = excluded.OwnerTeam,
                        OwnerNode = excluded.OwnerNode,
                        ForwardName = excluded.ForwardName,
                        InverseName = excluded.InverseName,
                        KeyType = excluded.KeyType;
                    """;
                ins.Parameters.AddWithValue("$code", algo.Code);
                ins.Parameters.AddWithValue("$aid", algo.AlgorithmId);
                ins.Parameters.AddWithValue("$name", algo.Name);
                ins.Parameters.AddWithValue("$cat", algo.Category);
                ins.Parameters.AddWithValue("$ot", (object?)algo.OwnerTeam ?? DBNull.Value);
                ins.Parameters.AddWithValue("$on", (object?)algo.OwnerNode ?? DBNull.Value);
                ins.Parameters.AddWithValue("$fn", algo.ForwardName);
                ins.Parameters.AddWithValue("$in", algo.InverseName);
                ins.Parameters.AddWithValue("$kt", algo.KeyType);
                ins.Parameters.AddWithValue("$key", algo.DefaultKey);
                ins.Parameters.AddWithValue("$now", now);
                ins.ExecuteNonQuery();
            }
        }
    }

    private static void EnsureColumn(SqliteConnection conn, string table, string col, string def)
    {
        using var check = conn.CreateCommand();
        check.CommandText = $"PRAGMA table_info({table});";
        using var r = check.ExecuteReader();
        while (r.Read())
        {
            if (string.Equals(r.GetString(1), col, StringComparison.OrdinalIgnoreCase)) return;
        }
        r.Close();
        using var alter = conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {col} {def};";
        alter.ExecuteNonQuery();
    }

    // --- Algorithms ---
    public List<AlgorithmConfig> GetAlgorithms()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT AlgorithmId, Code, Name, Category, OwnerTeam, OwnerNode, ForwardName, InverseName, KeyType, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc FROM AlgorithmConfigs ORDER BY AlgorithmId ASC;";
        using var r = cmd.ExecuteReader();
        var list = new List<AlgorithmConfig>();
        while (r.Read()) list.Add(ReadAlgorithm(r));
        return list;
    }

    public AlgorithmConfig? GetAlgorithm(string code)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT AlgorithmId, Code, Name, Category, OwnerTeam, OwnerNode, ForwardName, InverseName, KeyType, DefaultKey, IsVisible, CanEncrypt, CanDecrypt, UpdatedAtUtc FROM AlgorithmConfigs WHERE Code = $code;";
        cmd.Parameters.AddWithValue("$code", code.ToUpperInvariant());
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadAlgorithm(r) : null;
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
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
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
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            cmd.ExecuteNonQuery();
        }
    }

    public bool GetAdvancedMode()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Value FROM AppSettings WHERE Key = 'AdvancedMode' LIMIT 1;";
        var val = cmd.ExecuteScalar()?.ToString();
        return val == "1" || string.Equals(val, "true", StringComparison.OrdinalIgnoreCase);
    }

    public bool SetAdvancedMode(bool enabled)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO AppSettings (Key, Value) VALUES ('AdvancedMode', $val) ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;";
            cmd.Parameters.AddWithValue("$val", enabled ? "1" : "0");
            cmd.ExecuteNonQuery();
        }
        return enabled;
    }

    // --- Local Certificate (CN=EQ04) ---
    public DigitalCertificateRecord GetOrCreateLocalCertificate(Func<DigitalCertificateRecord> generator)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var sel = conn.CreateCommand();
            sel.CommandText = "SELECT Id, SubjectName, ThumbprintSha256, SerialNumber, IsLocalNode, CertificatePem, PrivateKeyPfxBase64, NotBeforeUtc, NotAfterUtc FROM DigitalCertificates WHERE IsLocalNode = 1 AND SubjectName LIKE '%CN=EQ04%' ORDER BY Id DESC LIMIT 1;";
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

    // --- SavedPackages (Consultas) ---
    public long AddSavedPackage(SavedPackageRecord rec)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO SavedPackages (ZipFileName, Origin, SourceNode, ProducerNode, SourceIp, PacketType, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes)
                VALUES ($file, $origin, $sn, $pn, $ip, $pt, $code, $name, $sha, $created, $bytes);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$file", rec.ZipFileName);
            cmd.Parameters.AddWithValue("$origin", rec.Origin);
            cmd.Parameters.AddWithValue("$sn", rec.SourceNode);
            cmd.Parameters.AddWithValue("$pn", rec.ProducerNode);
            cmd.Parameters.AddWithValue("$ip", rec.SourceIp);
            cmd.Parameters.AddWithValue("$pt", rec.PacketType);
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
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceNode, ProducerNode, SourceIp, PacketType, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt FROM SavedPackages ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<SavedPackageRecord>();
        while (r.Read())
        {
            list.Add(new SavedPackageRecord
            {
                Id = r.GetInt64(0),
                ZipFileName = r.GetString(1),
                Origin = r.GetString(2),
                SourceNode = r.GetString(3),
                ProducerNode = r.GetString(4),
                SourceIp = r.GetString(5),
                PacketType = r.GetString(6),
                AlgorithmCode = r.GetString(7),
                AlgorithmName = r.GetString(8),
                EncryptedSha256 = r.GetString(9),
                CreatedAt = r.GetString(10)
            });
        }
        return list;
    }

    public SavedPackageRecord? GetSavedPackageById(long id)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceNode, ProducerNode, SourceIp, PacketType, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes FROM SavedPackages WHERE Id = $id;";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new SavedPackageRecord
        {
            Id = r.GetInt64(0),
            ZipFileName = r.GetString(1),
            Origin = r.GetString(2),
            SourceNode = r.GetString(3),
            ProducerNode = r.GetString(4),
            SourceIp = r.GetString(5),
            PacketType = r.GetString(6),
            AlgorithmCode = r.GetString(7),
            AlgorithmName = r.GetString(8),
            EncryptedSha256 = r.GetString(9),
            CreatedAt = r.GetString(10),
            ZipBytes = (byte[])r["ZipBytes"]
        };
    }

    public List<SavedPackageRecord> GetAllSavedPackagesWithBytes()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, ZipFileName, Origin, SourceNode, ProducerNode, SourceIp, PacketType, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes FROM SavedPackages ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<SavedPackageRecord>();
        while (r.Read())
        {
            list.Add(new SavedPackageRecord
            {
                Id = r.GetInt64(0),
                ZipFileName = r.GetString(1),
                Origin = r.GetString(2),
                SourceNode = r.GetString(3),
                ProducerNode = r.GetString(4),
                SourceIp = r.GetString(5),
                PacketType = r.GetString(6),
                AlgorithmCode = r.GetString(7),
                AlgorithmName = r.GetString(8),
                EncryptedSha256 = r.GetString(9),
                CreatedAt = r.GetString(10),
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

    // --- IncomingRequests (Solicitudes) ---
    public long AddIncomingRequest(IncomingRequestRecord req)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO IncomingRequests (PacketId, SourceNode, SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, OperationName, SignatureValid, TrustStatus, Status, EncryptedSha256, ReceivedAt, ZipBytes)
                VALUES ($pid, $sn, $ip, $file, $code, $name, $op, $sig, $trust, $status, $sha, $rec, $bytes);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$pid", req.PacketId);
            cmd.Parameters.AddWithValue("$sn", req.SourceNode);
            cmd.Parameters.AddWithValue("$ip", req.SourceIp);
            cmd.Parameters.AddWithValue("$file", req.ZipFileName);
            cmd.Parameters.AddWithValue("$code", req.AlgorithmCode);
            cmd.Parameters.AddWithValue("$name", req.AlgorithmName);
            cmd.Parameters.AddWithValue("$op", req.OperationName);
            cmd.Parameters.AddWithValue("$sig", req.SignatureValid ? 1 : 0);
            cmd.Parameters.AddWithValue("$trust", req.TrustStatus);
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
        cmd.CommandText = "SELECT Id, PacketId, SourceNode, SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, OperationName, SignatureValid, TrustStatus, Status, EncryptedSha256, ReceivedAt FROM IncomingRequests ORDER BY Id DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<IncomingRequestRecord>();
        while (r.Read())
        {
            list.Add(new IncomingRequestRecord
            {
                Id = r.GetInt64(0),
                PacketId = r.GetString(1),
                SourceNode = r.GetString(2),
                SourceIp = r.GetString(3),
                ZipFileName = r.GetString(4),
                AlgorithmCode = r.GetString(5),
                AlgorithmName = r.GetString(6),
                OperationName = r.GetString(7),
                SignatureValid = r.GetInt32(8) == 1,
                TrustStatus = r.GetString(9),
                Status = r.GetString(10),
                EncryptedSha256 = r.GetString(11),
                ReceivedAt = r.GetString(12)
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
            sel.CommandText = "SELECT SourceNode, SourceIp, ZipFileName, AlgorithmCode, AlgorithmName, EncryptedSha256, Status, ZipBytes FROM IncomingRequests WHERE Id = $id;";
            sel.Parameters.AddWithValue("$id", requestId);
            using var r = sel.ExecuteReader();
            if (!r.Read()) return null;

            var status = r.GetString(6);
            var sourceNode = r.GetString(0);
            var sourceIp = r.GetString(1);
            var zipFileName = r.GetString(2);
            var algoCode = r.GetString(3);
            var algoName = r.GetString(4);
            var sha = r.GetString(5);
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
                INSERT INTO SavedPackages (ZipFileName, Origin, SourceNode, ProducerNode, SourceIp, PacketType, AlgorithmCode, AlgorithmName, EncryptedSha256, CreatedAt, ZipBytes)
                VALUES ($file, 'Recibido', $sn, $sn, $ip, 'package', $code, $name, $sha, $created, $bytes);
                SELECT last_insert_rowid();
                """;
            ins.Parameters.AddWithValue("$file", zipFileName);
            ins.Parameters.AddWithValue("$sn", sourceNode);
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
                SourceNode = sourceNode,
                ProducerNode = sourceNode,
                SourceIp = sourceIp,
                PacketType = "package",
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

    // --- DirectoryNodes (TOFU + Discovery) ---
    public List<DirectoryNodeRecord> GetDirectoryNodes()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT NodeId, TeamNumber, Ip, HttpPort, HttpsPort, CertificatePem, AnnouncedThumbprintSha256, PinnedThumbprintSha256, AlgorithmsJson, Source, Status, LastSeenUtc, TrustAlert FROM DirectoryNodes ORDER BY TeamNumber ASC;";
        using var r = cmd.ExecuteReader();
        var list = new List<DirectoryNodeRecord>();
        while (r.Read()) list.Add(ReadNode(r));
        return list;
    }

    public DirectoryNodeRecord? GetDirectoryNode(string nodeId)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT NodeId, TeamNumber, Ip, HttpPort, HttpsPort, CertificatePem, AnnouncedThumbprintSha256, PinnedThumbprintSha256, AlgorithmsJson, Source, Status, LastSeenUtc, TrustAlert FROM DirectoryNodes WHERE NodeId = $id;";
        cmd.Parameters.AddWithValue("$id", nodeId);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadNode(r) : null;
    }

    public DirectoryNodeRecord UpsertDirectoryNode(DirectoryNodeRecord node, bool autoPin = false)
    {
        lock (_writeLock)
        {
            var existing = GetDirectoryNode(node.NodeId);
            string? pinned = existing?.PinnedThumbprintSha256;
            bool trustAlert = false;

            if (autoPin)
            {
                pinned = node.AnnouncedThumbprintSha256;
                trustAlert = false;
            }
            else if (!string.IsNullOrEmpty(pinned) &&
                     !string.Equals(pinned, node.AnnouncedThumbprintSha256, StringComparison.OrdinalIgnoreCase))
            {
                trustAlert = true;
            }

            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO DirectoryNodes (NodeId, TeamNumber, Ip, HttpPort, HttpsPort, CertificatePem, AnnouncedThumbprintSha256, PinnedThumbprintSha256, AlgorithmsJson, Source, Status, LastSeenUtc, TrustAlert)
                VALUES ($id, $team, $ip, $http, $https, $pem, $ann, $pin, $algos, $src, $status, $seen, $alert)
                ON CONFLICT(NodeId) DO UPDATE SET
                    TeamNumber = excluded.TeamNumber,
                    Ip = excluded.Ip,
                    HttpPort = excluded.HttpPort,
                    HttpsPort = excluded.HttpsPort,
                    CertificatePem = excluded.CertificatePem,
                    AnnouncedThumbprintSha256 = excluded.AnnouncedThumbprintSha256,
                    PinnedThumbprintSha256 = excluded.PinnedThumbprintSha256,
                    AlgorithmsJson = excluded.AlgorithmsJson,
                    Source = excluded.Source,
                    Status = excluded.Status,
                    LastSeenUtc = excluded.LastSeenUtc,
                    TrustAlert = excluded.TrustAlert;
                """;
            cmd.Parameters.AddWithValue("$id", node.NodeId);
            cmd.Parameters.AddWithValue("$team", node.TeamNumber);
            cmd.Parameters.AddWithValue("$ip", node.Ip);
            cmd.Parameters.AddWithValue("$http", node.HttpPort);
            cmd.Parameters.AddWithValue("$https", (object?)node.HttpsPort ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$pem", node.CertificatePem);
            cmd.Parameters.AddWithValue("$ann", node.AnnouncedThumbprintSha256);
            cmd.Parameters.AddWithValue("$pin", (object?)pinned ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$algos", JsonSerializer.Serialize(node.Algorithms));
            cmd.Parameters.AddWithValue("$src", node.Source);
            cmd.Parameters.AddWithValue("$status", node.Status);
            cmd.Parameters.AddWithValue("$seen", node.LastSeenUtc);
            cmd.Parameters.AddWithValue("$alert", trustAlert ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
        return GetDirectoryNode(node.NodeId)!;
    }

    public DirectoryNodeRecord? ConfirmNodeTrust(string nodeId)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE DirectoryNodes SET PinnedThumbprintSha256 = AnnouncedThumbprintSha256, TrustAlert = 0 WHERE NodeId = $id;";
            cmd.Parameters.AddWithValue("$id", nodeId);
            if (cmd.ExecuteNonQuery() == 0) return null;
        }
        return GetDirectoryNode(nodeId);
    }

    public bool DeleteDirectoryNode(string nodeId)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM DirectoryNodes WHERE NodeId = $id;";
            cmd.Parameters.AddWithValue("$id", nodeId);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public void MarkStaleNodesOffline(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow.Subtract(maxAge).ToString("yyyy-MM-ddTHH:mm:ssZ");
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE DirectoryNodes SET Status = 'offline' WHERE Status = 'online' AND LastSeenUtc < $cutoff;";
            cmd.Parameters.AddWithValue("$cutoff", cutoff);
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkNodeOffline(string nodeId)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE DirectoryNodes SET Status = 'offline' WHERE NodeId = $id;";
            cmd.Parameters.AddWithValue("$id", nodeId);
            cmd.ExecuteNonQuery();
        }
    }

    // --- Replay Protection (SeenIds) ---
    public bool TryRegisterSeenId(string id, string kind)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT OR IGNORE INTO SeenIds (Id, Kind, SeenAtUtc) VALUES ($id, $kind, $now);";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$kind", kind);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public bool IsSeenId(string id)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM SeenIds WHERE Id = $id LIMIT 1;";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteScalar() is not null;
    }

    // --- Asymmetric Keys (keyId, sección 12) ---
    public void SaveAsymmetricKey(AsymmetricKeyRecord key)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO AsymmetricKeys (KeyId, AlgorithmCode, OwnerNode, PublicParamsJson, PrivateParamsJson, AllowedNodes, CreatedAtUtc)
                VALUES ($kid, $code, $owner, $pub, $priv, $allowed, $now);
                """;
            cmd.Parameters.AddWithValue("$kid", key.KeyId);
            cmd.Parameters.AddWithValue("$code", key.AlgorithmCode);
            cmd.Parameters.AddWithValue("$owner", key.OwnerNode);
            cmd.Parameters.AddWithValue("$pub", key.PublicParamsJson);
            cmd.Parameters.AddWithValue("$priv", key.PrivateParamsJson);
            cmd.Parameters.AddWithValue("$allowed", (object?)key.AllowedNodes ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$now", key.CreatedAtUtc);
            cmd.ExecuteNonQuery();
        }
    }

    public AsymmetricKeyRecord? GetAsymmetricKey(string keyId)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT KeyId, AlgorithmCode, OwnerNode, PublicParamsJson, PrivateParamsJson, AllowedNodes, CreatedAtUtc FROM AsymmetricKeys WHERE KeyId = $kid;";
        cmd.Parameters.AddWithValue("$kid", keyId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new AsymmetricKeyRecord
        {
            KeyId = r.GetString(0),
            AlgorithmCode = r.GetString(1),
            OwnerNode = r.GetString(2),
            PublicParamsJson = r.GetString(3),
            PrivateParamsJson = r.GetString(4),
            AllowedNodes = r.IsDBNull(5) ? null : r.GetString(5),
            CreatedAtUtc = r.GetString(6)
        };
    }

    // --- Async Jobs (sección 10.7) ---
    public void SaveAsyncJob(AsyncJobRecord job)
    {
        lock (_writeLock)
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO AsyncJobs (JobId, RequesterNode, State, ProgressPercent, ErrorJson, ResultZipBytes, ResultFileName, CreatedAtUtc)
                VALUES ($id, $req, $st, $prog, $err, $bytes, $fname, $now)
                ON CONFLICT(JobId) DO UPDATE SET
                    State = excluded.State,
                    ProgressPercent = excluded.ProgressPercent,
                    ErrorJson = excluded.ErrorJson,
                    ResultZipBytes = excluded.ResultZipBytes,
                    ResultFileName = excluded.ResultFileName;
                """;
            cmd.Parameters.AddWithValue("$id", job.JobId);
            cmd.Parameters.AddWithValue("$req", job.RequesterNode);
            cmd.Parameters.AddWithValue("$st", job.State);
            cmd.Parameters.AddWithValue("$prog", job.ProgressPercent);
            cmd.Parameters.AddWithValue("$err", (object?)job.ErrorJson ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$bytes", (object?)job.ResultZipBytes ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$fname", (object?)job.ResultFileName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$now", job.CreatedAtUtc);
            cmd.ExecuteNonQuery();
        }
    }

    public AsyncJobRecord? GetAsyncJob(string jobId)
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT JobId, RequesterNode, State, ProgressPercent, ErrorJson, ResultZipBytes, ResultFileName, CreatedAtUtc FROM AsyncJobs WHERE JobId = $id;";
        cmd.Parameters.AddWithValue("$id", jobId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new AsyncJobRecord
        {
            JobId = r.GetString(0),
            RequesterNode = r.GetString(1),
            State = r.GetString(2),
            ProgressPercent = r.GetInt32(3),
            ErrorJson = r.IsDBNull(4) ? null : r.GetString(4),
            ResultZipBytes = r.IsDBNull(5) ? null : (byte[])r["ResultZipBytes"],
            ResultFileName = r.IsDBNull(6) ? null : r.GetString(6),
            CreatedAtUtc = r.GetString(7)
        };
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
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            cmd.ExecuteNonQuery();
        }
    }

    private static AlgorithmConfig ReadAlgorithm(SqliteDataReader r) => new()
    {
        AlgorithmId = r.GetInt32(0),
        Code = r.GetString(1),
        Name = r.GetString(2),
        Category = r.GetString(3),
        OwnerTeam = r.IsDBNull(4) ? null : r.GetInt32(4),
        OwnerNode = r.IsDBNull(5) ? null : r.GetString(5),
        ForwardName = r.GetString(6),
        InverseName = r.GetString(7),
        KeyType = r.GetString(8),
        DefaultKey = r.GetString(9),
        IsVisible = r.GetInt32(10) == 1,
        CanEncrypt = r.GetInt32(11) == 1,
        CanDecrypt = r.GetInt32(12) == 1,
        UpdatedAtUtc = r.GetString(13)
    };

    private static DirectoryNodeRecord ReadNode(SqliteDataReader r) => new()
    {
        NodeId = r.GetString(0),
        TeamNumber = r.GetInt32(1),
        Ip = r.GetString(2),
        HttpPort = r.GetInt32(3),
        HttpsPort = r.IsDBNull(4) ? null : r.GetInt32(4),
        CertificatePem = r.GetString(5),
        AnnouncedThumbprintSha256 = r.GetString(6),
        PinnedThumbprintSha256 = r.IsDBNull(7) ? null : r.GetString(7),
        Algorithms = JsonSerializer.Deserialize<List<string>>(r.GetString(8)) ?? new List<string>(),
        Source = r.GetString(9),
        Status = r.GetString(10),
        LastSeenUtc = r.GetString(11),
        TrustAlert = r.GetInt32(12) == 1
    };
}
