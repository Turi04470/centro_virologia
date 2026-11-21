using System.Text.Json.Serialization;

namespace CentroCiberseguridad.Web.Models;

public sealed class AlgorithmConfig
{
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string DefaultKey { get; set; } = string.Empty;
    public bool IsVisible { get; set; } = true;
    public bool CanEncrypt { get; set; } = true;
    public bool CanDecrypt { get; set; } = true;
    public string UpdatedAtUtc { get; set; } = string.Empty;
}

public sealed class UpdateAlgorithmRequest
{
    public bool IsVisible { get; set; }
    public bool CanEncrypt { get; set; }
    public bool CanDecrypt { get; set; }
}

public sealed class OperateRequest
{
    public string AlgorithmCode { get; set; } = "AESGCM";
    public bool IsEncrypt { get; set; } = true;
    public string InputMode { get; set; } = "text";
    public string? Text { get; set; }
    public string? FileBase64 { get; set; }
    public string? FileName { get; set; }
    public string Key { get; set; } = string.Empty;
    public bool AttachCertificate { get; set; } = true;
}

public sealed class OperateResponse
{
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public bool IsEncrypt { get; set; }
    public string? OutputText { get; set; }
    public string? OutputBase64 { get; set; }
    public string OutputFileName { get; set; } = "salida.bin";
    public string Sha256 { get; set; } = string.Empty;
    public string? ZipFileName { get; set; }
    public long? ConsultaId { get; set; }
    public string[] Cells { get; set; } = Array.Empty<string>();
    public string[] Steps { get; set; } = Array.Empty<string>();
    public SignedManifest? Manifest { get; set; }
}

public sealed class SignedManifest
{
    public string Version { get; set; } = "1.0";
    public string PacketId { get; set; } = string.Empty;
    public string SourceNode { get; set; } = "NODO-04";
    public string SourceIp { get; set; } = "127.0.0.1:5000";
    public string TimestampUtc { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public string AlgorithmCode { get; set; } = string.Empty;
    public string PayloadMode { get; set; } = "text";
    public string OriginalFileName { get; set; } = "datos.txt";
    public string OriginalExtension { get; set; } = ".txt";
    public long OriginalSizeBytes { get; set; }
    public string EncryptedSha256 { get; set; } = string.Empty;
    public Dictionary<string, string> PublicParameters { get; set; } = new();
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = "RSA-PSS-SHA256";
    public string ManifestSignatureBase64 { get; set; } = string.Empty;
}

public sealed class DigitalCertificateRecord
{
    public int Id { get; set; }
    public string SubjectName { get; set; } = string.Empty;
    public string ThumbprintSha256 { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public bool IsLocalNode { get; set; }
    public string CertificatePem { get; set; } = string.Empty;
    [JsonIgnore]
    public string PrivateKeyPfxBase64 { get; set; } = string.Empty;
    public string NotBeforeUtc { get; set; } = string.Empty;
    public string NotAfterUtc { get; set; } = string.Empty;
}

public sealed class SavedPackageRecord
{
    public long Id { get; set; }
    public string ZipFileName { get; set; } = string.Empty;
    public string Origin { get; set; } = "Local";
    public string SourceIp { get; set; } = "127.0.0.1";
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public string EncryptedSha256 { get; set; } = string.Empty;
    public string CreatedAt { get; set; } = string.Empty;
    [JsonIgnore]
    public byte[] ZipBytes { get; set; } = Array.Empty<byte>();
}

public sealed class IncomingRequestRecord
{
    public long Id { get; set; }
    public string PacketId { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public string ZipFileName { get; set; } = string.Empty;
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public bool SignatureValid { get; set; }
    public string Status { get; set; } = "Pendiente";
    public string EncryptedSha256 { get; set; } = string.Empty;
    public string ReceivedAt { get; set; } = string.Empty;
    [JsonIgnore]
    public byte[] ZipBytes { get; set; } = Array.Empty<byte>();
}

public sealed class SendZipRequest
{
    public string TargetIp { get; set; } = string.Empty;
}

public sealed class ZipValidationResult
{
    public bool IsValid { get; set; }
    public int HttpStatusCode { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public SignedManifest? Manifest { get; set; }
    public byte[] EncryptedBytes { get; set; } = Array.Empty<byte>();
    public string CertificatePem { get; set; } = string.Empty;
}

public sealed class UnpackedPackageResponse
{
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public string PayloadMode { get; set; } = "text";
    public string OriginalFileName { get; set; } = "datos.txt";
    public string DataText { get; set; } = string.Empty;
    public string DataBase64 { get; set; } = string.Empty;
    public string EncryptedSha256 { get; set; } = string.Empty;
    public bool SignatureValid { get; set; }
}
