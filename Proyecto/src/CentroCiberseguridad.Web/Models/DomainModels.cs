using System.Text.Json.Serialization;

namespace CentroCiberseguridad.Web.Models;

public sealed class AlgorithmConfig
{
    public int AlgorithmId { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public int? OwnerTeam { get; set; }
    public string? OwnerNode { get; set; }
    public string ForwardName { get; set; } = "cifrar";
    public string InverseName { get; set; } = "descifrar";
    public string KeyType { get; set; } = "Secreta";
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

public sealed class AdvancedModeRequest
{
    public bool Enabled { get; set; }
}

public sealed class OperateRequest
{
    public string AlgorithmCode { get; set; } = "CAESAR";
    public bool IsEncrypt { get; set; } = true;
    public string InputMode { get; set; } = "text";
    public string? Text { get; set; }
    public string? FileBase64 { get; set; }
    public string? FileName { get; set; }
    public string Key { get; set; } = string.Empty;
    public bool AttachCertificate { get; set; } = true;
    public long? SourceConsultaId { get; set; }
    public string? KeyId { get; set; }
}

public sealed class OperateResponse
{
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public bool IsEncrypt { get; set; }
    public string ExecutionMode { get; set; } = "local";
    public string ProducerNode { get; set; } = "EQ04";
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

public sealed class MultipartPartInfo
{
    public string Name { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
}

public sealed class KeyRefInfo
{
    public string KeyId { get; set; } = string.Empty;
    public string OwnerNode { get; set; } = string.Empty;
}

public sealed class VerificationInfo
{
    public bool Valid { get; set; }
    public string Detail { get; set; } = string.Empty;
}

public sealed class CcEnvelope
{
    public string Envelope { get; set; } = "CC-ENV-1";
    public string RecipientNode { get; set; } = string.Empty;
    public string RecipientThumbprintSha256 { get; set; } = string.Empty;
    public string WrappedKeyBase64 { get; set; } = string.Empty;
    public string NonceBase64 { get; set; } = string.Empty;
    public string TagBase64 { get; set; } = string.Empty;
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CiphertextBase64 { get; set; }
}

public sealed class SignedManifest
{
    public string Version { get; set; } = "2.0";
    public string PacketType { get; set; } = "package";
    public string PacketId { get; set; } = string.Empty;
    public string? RequestId { get; set; }
    public string SourceNode { get; set; } = "EQ04";
    public int SourceTeam { get; set; } = 4;
    public string SourceIp { get; set; } = "127.0.0.1:5004";
    public string ProducerNode { get; set; } = "EQ04";
    public string TimestampUtc { get; set; } = string.Empty;
    public int AlgorithmId { get; set; }
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public string Operation { get; set; } = "forward";
    public string OperationName { get; set; } = "cifrar";
    public string PayloadMode { get; set; } = "text";
    public string OriginalFileName { get; set; } = "mensaje.txt";
    public string OriginalExtension { get; set; } = ".txt";
    public long OriginalSizeBytes { get; set; }
    public string ContentType { get; set; } = "text/plain";
    public string EncryptedSha256 { get; set; } = string.Empty;
    public long EncryptedSizeBytes { get; set; }
    public List<MultipartPartInfo>? Parts { get; set; }
    public KeyRefInfo? KeyRef { get; set; }
    public Dictionary<string, string> PublicParameters { get; set; } = new();
    public string PublicParametersSha256 { get; set; } = string.Empty;
    public VerificationInfo? Verification { get; set; }
    public CcEnvelope? ResultEnvelope { get; set; }
    public string CertificateThumbprintSha256 { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = "RSA-PSS-SHA256";
    public string ManifestSignatureBase64 { get; set; } = string.Empty;
}

public sealed class CryptoRemoteRequestDto
{
    public string Version { get; set; } = "2.0";
    public string RequestId { get; set; } = string.Empty;
    public string RequesterNode { get; set; } = string.Empty;
    public string TargetNode { get; set; } = string.Empty;
    public string TimestampUtc { get; set; } = string.Empty;
    public string AlgorithmCode { get; set; } = string.Empty;
    public string Operation { get; set; } = "forward";
    public string PayloadMode { get; set; } = "text";
    public string OriginalFileName { get; set; } = "mensaje.txt";
    public Dictionary<string, string> Options { get; set; } = new();
    public string? KeyId { get; set; }
    public CcEnvelope? Secrets { get; set; }
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
    public string Origin { get; set; } = "Generado";
    public string SourceNode { get; set; } = "EQ04";
    public string ProducerNode { get; set; } = "EQ04";
    public string SourceIp { get; set; } = "127.0.0.1:5004";
    public string PacketType { get; set; } = "package";
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
    public string SourceNode { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public string ZipFileName { get; set; } = string.Empty;
    public string AlgorithmCode { get; set; } = string.Empty;
    public string AlgorithmName { get; set; } = string.Empty;
    public string OperationName { get; set; } = "cifrar";
    public bool SignatureValid { get; set; }
    public string TrustStatus { get; set; } = "Firma OK";
    public string Status { get; set; } = "Pendiente";
    public string EncryptedSha256 { get; set; } = string.Empty;
    public string ReceivedAt { get; set; } = string.Empty;
    [JsonIgnore]
    public byte[] ZipBytes { get; set; } = Array.Empty<byte>();
}

public sealed class DirectoryNodeRecord
{
    public string NodeId { get; set; } = string.Empty;
    public int TeamNumber { get; set; }
    public string Ip { get; set; } = string.Empty;
    public int HttpPort { get; set; }
    public int? HttpsPort { get; set; }
    public string CertificatePem { get; set; } = string.Empty;
    public string AnnouncedThumbprintSha256 { get; set; } = string.Empty;
    public string? PinnedThumbprintSha256 { get; set; }
    public List<string> Algorithms { get; set; } = new();
    public string Source { get; set; } = "manual";
    public string Status { get; set; } = "online";
    public string LastSeenUtc { get; set; } = string.Empty;
    public bool TrustAlert { get; set; }
}

public sealed class AsymmetricKeyRecord
{
    public string KeyId { get; set; } = string.Empty;
    public string AlgorithmCode { get; set; } = string.Empty;
    public string OwnerNode { get; set; } = "EQ04";
    public string PublicParamsJson { get; set; } = "{}";
    [JsonIgnore]
    public string PrivateParamsJson { get; set; } = "{}";
    public string? AllowedNodes { get; set; }
    public string CreatedAtUtc { get; set; } = string.Empty;
}

public sealed class AsyncJobRecord
{
    public string JobId { get; set; } = string.Empty;
    public string RequesterNode { get; set; } = string.Empty;
    public string State { get; set; } = "queued";
    public int ProgressPercent { get; set; }
    public string? ErrorJson { get; set; }
    [JsonIgnore]
    public byte[]? ResultZipBytes { get; set; }
    public string? ResultFileName { get; set; }
    public string CreatedAtUtc { get; set; } = string.Empty;
}

public sealed class SendZipRequest
{
    public string? TargetIp { get; set; }
    public string? TargetNodeId { get; set; }
}

public sealed class ManualNodeRequest
{
    public string Ip { get; set; } = string.Empty;
    public int Port { get; set; }
}

public sealed class ZipValidationResult
{
    public bool IsValid { get; set; }
    public int HttpStatusCode { get; set; }
    public string ErrorCode { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string TrustStatus { get; set; } = "Firma OK";
    public SignedManifest? Manifest { get; set; }
    public byte[] PayloadBytes { get; set; } = Array.Empty<byte>();
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
    public string? KeyId { get; set; }
    public SignedManifest? Manifest { get; set; }
}

public sealed class ProtocolException : Exception
{
    public string ErrorCode { get; }
    public int HttpStatusCode { get; }
    public string Title { get; }

    public ProtocolException(string errorCode, int httpStatusCode, string title, string detail)
        : base(detail)
    {
        ErrorCode = errorCode;
        HttpStatusCode = httpStatusCode;
        Title = title;
    }
}
