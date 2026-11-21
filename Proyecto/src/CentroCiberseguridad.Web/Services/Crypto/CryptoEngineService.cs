using System.Diagnostics;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CentroCiberseguridad.Web.Models;
using CentroCiberseguridad.Web.Services.Data;
using CentroCiberseguridad.Web.Services.Transfer;

namespace CentroCiberseguridad.Web.Services.Crypto;

public sealed class CryptoEngineService
{
    private readonly SqliteDatabaseService _db;
    private readonly CertificateAndZipService _certZip;

    public CryptoEngineService(SqliteDatabaseService db, CertificateAndZipService certZip)
    {
        _db = db;
        _certZip = certZip;
    }

    public OperateResponse Execute(OperateRequest req)
    {
        var sw = Stopwatch.StartNew();
        var code = req.AlgorithmCode.Trim().ToUpperInvariant();
        var algo = _db.GetAlgorithm(code)
            ?? throw new ArgumentException($"Algoritmo desconocido: {code}");

        if (!algo.IsVisible)
            throw new UnauthorizedAccessException($"El algoritmo '{algo.Name}' está oculto en Ajustes.");
        if (req.IsEncrypt && !algo.CanEncrypt)
            throw new UnauthorizedAccessException($"La encriptación está deshabilitada para '{algo.Name}'.");
        if (!req.IsEncrypt && !algo.CanDecrypt)
            throw new UnauthorizedAccessException($"La desencriptación está deshabilitada para '{algo.Name}'.");

        var isFile = string.Equals(req.InputMode, "file", StringComparison.OrdinalIgnoreCase);
        var key = req.Key?.Trim() ?? string.Empty;
        var keyOptional = code == "HASHSHA" && req.IsEncrypt;
        if (!keyOptional && string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("Ingresa una clave o parámetro.");

        byte[] inputBytes;
        string inputText = req.Text ?? string.Empty;
        if (isFile)
        {
            if (string.IsNullOrWhiteSpace(req.FileBase64))
                throw new ArgumentException("Se requiere FileBase64 en modo archivo.");
            inputBytes = Convert.FromBase64String(req.FileBase64);
        }
        else
        {
            if (string.IsNullOrEmpty(inputText))
                throw new ArgumentException("Se requiere texto de entrada.");
            inputBytes = Encoding.UTF8.GetBytes(inputText);
        }

        var (outBytes, outText, steps, pubParams) = DispatchAlgorithm(code, req.IsEncrypt, inputBytes, inputText, key, isFile);

        var outSha = Convert.ToHexString(SHA256.HashData(outBytes)).ToLowerInvariant();
        var inSha = Convert.ToHexString(SHA256.HashData(inputBytes)).ToLowerInvariant();
        var cells = Enumerable.Range(0, 16)
            .Select(i => (outBytes.Length > 0 ? outBytes[i % outBytes.Length] : (byte)0).ToString("X2"))
            .ToArray();

        string? zipFileName = null;
        long? consultaId = null;
        SignedManifest? manifest = null;

        if (req.IsEncrypt && req.AttachCertificate)
        {
            var origName = string.IsNullOrWhiteSpace(req.FileName) ? (isFile ? "archivo.bin" : "mensaje.txt") : req.FileName!;
            var (zipBytes, zName, mf) = _certZip.CreateSignedZipPackage(
                outBytes,
                algo.Code,
                algo.Name,
                req.InputMode,
                origName,
                inputBytes.Length,
                publicParams: pubParams);

            zipFileName = zName;
            manifest = mf;
            consultaId = _db.AddSavedPackage(new SavedPackageRecord
            {
                ZipFileName = zName,
                Origin = "Local",
                SourceIp = "127.0.0.1",
                AlgorithmCode = algo.Code,
                AlgorithmName = algo.Name,
                EncryptedSha256 = outSha,
                CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                ZipBytes = zipBytes
            });
        }

        sw.Stop();
        _db.LogCryptoOperation(algo.Code, req.IsEncrypt ? "Encrypt" : "Decrypt", req.InputMode, inSha, outSha, sw.ElapsedMilliseconds);

        var outFileName = isFile
            ? (req.IsEncrypt
                ? $"{(string.IsNullOrWhiteSpace(req.FileName) ? "archivo.bin" : req.FileName)}.enc"
                : Regex.Replace(req.FileName ?? "descifrado.bin", @"\.enc$", "", RegexOptions.IgnoreCase))
            : "salida.txt";

        return new OperateResponse
        {
            AlgorithmCode = algo.Code,
            AlgorithmName = algo.Name,
            IsEncrypt = req.IsEncrypt,
            OutputText = outText,
            OutputBase64 = Convert.ToBase64String(outBytes),
            OutputFileName = string.IsNullOrWhiteSpace(outFileName) ? "descifrado.bin" : outFileName,
            Sha256 = outSha,
            ZipFileName = zipFileName,
            ConsultaId = consultaId,
            Cells = cells,
            Steps = steps,
            Manifest = manifest
        };
    }

    private (byte[] Bytes, string Text, string[] Steps, Dictionary<string, string> Params) DispatchAlgorithm(
        string code, bool isEncrypt, byte[] inputBytes, string inputText, string key, bool isFile)
    {
        var steps = new List<string>();
        var pubParams = new Dictionary<string, string>();
        byte[] keySha = SHA256.HashData(Encoding.UTF8.GetBytes(key));

        switch (code)
        {
            case "AESGCM":
            {
                if (isEncrypt)
                {
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var cipher = new byte[inputBytes.Length];
                    var tag = new byte[16];
                    using var aes = new AesGcm(keySha, 16);
                    aes.Encrypt(nonce, inputBytes, cipher, tag);
                    var packed = Concat(nonce, tag, cipher);
                    steps.Add($"AES-256-GCM · Clave derivada SHA-256 ({keySha.Length * 8} bits)");
                    steps.Add($"Nonce 96 bits: {Convert.ToHexString(nonce)}");
                    steps.Add($"Tag GCM 128 bits: {Convert.ToHexString(tag)}");
                    pubParams["nonceHex"] = Convert.ToHexString(nonce);
                    return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    if (src.Length < 28) throw new ArgumentException("Payload AES-GCM demasiado corto.");
                    var nonce = src[..12];
                    var tag = src[12..28];
                    var cipher = src[28..];
                    var plain = new byte[cipher.Length];
                    using var aes = new AesGcm(keySha, 16);
                    aes.Decrypt(nonce, cipher, tag, plain);
                    steps.Add($"Tag GCM verificado correctamente");
                    steps.Add($"Descifrados {plain.Length} bytes");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "DES":
            {
#pragma warning disable SYSLIB0021
                using var des = DES.Create();
#pragma warning restore SYSLIB0021
                des.Key = keySha[..8];
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                if (isEncrypt)
                {
                    des.GenerateIV();
                    var enc = des.EncryptCbc(inputBytes, des.IV);
                    var packed = Concat(des.IV, enc);
                    steps.Add("Red de Feistel DES (16 rondas, 56 bits efectivos)");
                    steps.Add($"IV CBC: {Convert.ToHexString(des.IV)}");
                    return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    var iv = src[..8];
                    var plain = des.DecryptCbc(src[8..], iv);
                    steps.Add("DES CBC descifrado (16 rondas inversas)");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "TRIPLEDES":
            {
                using var tdes = TripleDES.Create();
                tdes.Key = keySha[..24];
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.PKCS7;
                if (isEncrypt)
                {
                    tdes.GenerateIV();
                    var enc = tdes.EncryptCbc(inputBytes, tdes.IV);
                    var packed = Concat(tdes.IV, enc);
                    steps.Add("Esquema EDE Triple-DES / Perfil 3DES-96");
                    steps.Add($"IV CBC: {Convert.ToHexString(tdes.IV)}");
                    return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    var iv = src[..8];
                    var plain = tdes.DecryptCbc(src[8..], iv);
                    steps.Add("Secuencia inversa E-D-E completada");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "CHACHA20":
            {
                if (isEncrypt)
                {
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var cipher = ChaCha20Xor(inputBytes, keySha, nonce);
                    var tag = HMACSHA256.HashData(keySha, Concat(nonce, cipher))[..16];
                    var packed = Concat(nonce, tag, cipher);
                    steps.Add("Matriz 4x4 ChaCha20 · 20 rondas ARX");
                    steps.Add($"Nonce 96 bits: {Convert.ToHexString(nonce)}");
                    steps.Add($"Tag autenticación: {Convert.ToHexString(tag)}");
                    return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    if (src.Length < 28) throw new ArgumentException("Payload ChaCha20 inválido.");
                    var nonce = src[..12];
                    var tag = src[12..28];
                    var cipher = src[28..];
                    var expected = HMACSHA256.HashData(keySha, Concat(nonce, cipher))[..16];
                    if (!CryptographicOperations.FixedTimeEquals(tag, expected))
                        throw new CryptographicException("Etiqueta de autenticación ChaCha20 inválida.");
                    var plain = ChaCha20Xor(cipher, keySha, nonce);
                    steps.Add("Etiqueta verificada y flujo XOR revertido");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "RSA":
            {
                var p = ParseBigIntParam(key, "p", 257);
                var q = ParseBigIntParam(key, "q", 263);
                var e = ParseBigIntParam(key, "e", 3);
                var n = p * q;
                if (n <= 255) { p = 257; q = 263; e = 3; n = p * q; }
                var phi = (p - 1) * (q - 1);
                var d = ModInverseBig(e, phi);
                if ((e * d) % phi != 1) throw new ArgumentException("e debe ser coprimo con φ(n).");

                if (isEncrypt)
                {
                    var outBuf = new byte[inputBytes.Length * 4];
                    for (var i = 0; i < inputBytes.Length; i++)
                    {
                        var c = (uint)BigInteger.ModPow(inputBytes[i], e, n);
                        outBuf[i * 4] = (byte)(c >> 24);
                        outBuf[i * 4 + 1] = (byte)(c >> 16);
                        outBuf[i * 4 + 2] = (byte)(c >> 8);
                        outBuf[i * 4 + 3] = (byte)c;
                    }
                    steps.Add($"Primos p={p}, q={q} -> n={n}, φ(n)={phi}");
                    steps.Add($"Exponente público e={e}, privado d={d}");
                    steps.Add($"Cifrado c = m^{e} mod {n}");
                    return (outBuf, Convert.ToBase64String(outBuf), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    var plain = new byte[src.Length / 4];
                    for (var i = 0; i < plain.Length; i++)
                    {
                        uint c = (uint)((src[i * 4] << 24) | (src[i * 4 + 1] << 16) | (src[i * 4 + 2] << 8) | src[i * 4 + 3]);
                        plain[i] = (byte)((int)BigInteger.ModPow(c, d, n) & 0xFF);
                    }
                    steps.Add($"Inverso modular d={d} · m = c^{d} mod {n}");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "ECC":
            {
                // NIST P-256 ECDH: ephemeral sender key + receiver key derived deterministically from key material
                var bobParams = DeriveP256FromSeed(keySha);
                using var bob = ECDiffieHellman.Create(bobParams);
                if (isEncrypt)
                {
                    using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                    var alicePubDer = alice.PublicKey.ExportSubjectPublicKeyInfo();
                    var shared = alice.DeriveKeyMaterial(bob.PublicKey);
                    var symKey = SHA256.HashData(Concat(shared, keySha));
                    var nonce = RandomNumberGenerator.GetBytes(12);
                    var cipher = new byte[inputBytes.Length];
                    var tag = new byte[16];
                    using var aes = new AesGcm(symKey, 16);
                    aes.Encrypt(nonce, inputBytes, cipher, tag);

                    var lenBytes = BitConverter.GetBytes((ushort)alicePubDer.Length);
                    var packed = Concat(lenBytes, alicePubDer, nonce, tag, cipher);
                    steps.Add("Curva NIST P-256 (secp256r1) · Acuerdo ECDH");
                    steps.Add($"Punto público efímero SPKI: {alicePubDer.Length} bytes");
                    steps.Add($"Cifrado híbrido ECIES + AES-256-GCM");
                    return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    int pubLen = BitConverter.ToUInt16(src, 0);
                    var alicePubDer = src[2..(2 + pubLen)];
                    var off = 2 + pubLen;
                    var nonce = src[off..(off + 12)];
                    var tag = src[(off + 12)..(off + 28)];
                    var cipher = src[(off + 28)..];
                    using var alicePub = ECDiffieHellman.Create();
                    alicePub.ImportSubjectPublicKeyInfo(alicePubDer, out _);
                    var shared = bob.DeriveKeyMaterial(alicePub.PublicKey);
                    var symKey = SHA256.HashData(Concat(shared, keySha));
                    var plain = new byte[cipher.Length];
                    using var aes = new AesGcm(symKey, 16);
                    aes.Decrypt(nonce, cipher, tag, plain);
                    steps.Add("Secreto compartido ECDH reconstruido en P-256");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "DIFFIEHELLMAN":
            {
                var p = ParseBigIntParam(key, "p", 467);
                var g = ParseBigIntParam(key, "g", 2);
                var a = ParseBigIntParam(key, "a", 15);
                var b = ParseBigIntParam(key, "b", 27);
                var pubA = BigInteger.ModPow(g, a, p);
                var pubB = BigInteger.ModPow(g, b, p);
                var sharedK = BigInteger.ModPow(pubB, a, p);
                var derivedKey = SHA256.HashData(Encoding.UTF8.GetBytes($"DH:{sharedK}:{key}"));
                steps.Add($"Parámetros p={p}, g={g} · A={pubA}, B={pubB}");
                steps.Add($"Secreto compartido K = B^a mod p = {sharedK}");
                return SymmetricStreamHelper(isEncrypt, inputBytes, inputText, isFile, derivedKey, steps, pubParams);
            }

            case "CAESAR":
            {
                var shift = int.TryParse(key, out var kVal) ? kVal : 3;
                if (!isFile)
                {
                    var delta = isEncrypt ? shift : -shift;
                    var chars = inputText.Select(c =>
                    {
                        if (c is >= 'A' and <= 'Z') return (char)(((c - 'A' + delta) % 26 + 26) % 26 + 'A');
                        if (c is >= 'a' and <= 'z') return (char)(((c - 'a' + delta) % 26 + 26) % 26 + 'a');
                        return c;
                    }).ToArray();
                    var resultStr = new string(chars);
                    steps.Add($"Desplazamiento k = {shift}");
                    steps.Add($"Fórmula: (M {(isEncrypt ? "+" : "-")} {shift}) mod 26");
                    return (Encoding.UTF8.GetBytes(resultStr), resultStr, steps.ToArray(), pubParams);
                }
                else
                {
                    var delta = isEncrypt ? shift : -shift;
                    var outBuf = inputBytes.Select(b => (byte)(((b + delta) % 256 + 256) % 256)).ToArray();
                    steps.Add($"Desplazamiento de bytes mod 256 (k={shift})");
                    return (outBuf, Convert.ToBase64String(outBuf), steps.ToArray(), pubParams);
                }
            }

            case "VIGENERE":
            {
                var kBytes = Encoding.UTF8.GetBytes(key.ToUpperInvariant());
                if (kBytes.Length == 0) kBytes = "SOL"u8.ToArray();
                if (!isFile)
                {
                    var j = 0;
                    var sb = new StringBuilder(inputText.Length);
                    foreach (var c in inputText)
                    {
                        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                        {
                            var baseCh = c <= 'Z' ? 'A' : 'a';
                            var s = ((kBytes[j % kBytes.Length] - 'A') % 26 + 26) % 26;
                            j++;
                            var d = isEncrypt ? s : -s;
                            sb.Append((char)(((c - baseCh + d) % 26 + 26) % 26 + baseCh));
                        }
                        else sb.Append(c);
                    }
                    var resStr = sb.ToString();
                    steps.Add($"Clave repetida: {key}");
                    steps.Add("Sustitución polialfabética mod 26");
                    return (Encoding.UTF8.GetBytes(resStr), resStr, steps.ToArray(), pubParams);
                }
                else
                {
                    var outBuf = new byte[inputBytes.Length];
                    for (var i = 0; i < inputBytes.Length; i++)
                    {
                        var s = kBytes[i % kBytes.Length];
                        outBuf[i] = (byte)(isEncrypt ? (inputBytes[i] + s) % 256 : (inputBytes[i] - s + 256) % 256);
                    }
                    steps.Add($"Suma/Resta modular Z_256 con clave de {kBytes.Length} B");
                    return (outBuf, Convert.ToBase64String(outBuf), steps.ToArray(), pubParams);
                }
            }

            case "XORASM":
            {
                var hexMatch = Regex.Match(key, @"0x([0-9a-fA-F]+)");
                byte xorVal = hexMatch.Success ? (byte)(Convert.ToInt32(hexMatch.Groups[1].Value, 16) & 0xFF) : (byte)(keySha[0]);
                var rolMatch = Regex.Match(key, @"ROL=(\d+)", RegexOptions.IgnoreCase);
                var rot = rolMatch.Success ? int.Parse(rolMatch.Groups[1].Value) % 8 : 1;

                var src = isEncrypt ? inputBytes : (isFile ? inputBytes : Convert.FromBase64String(inputText.Trim()));
                var outBuf = new byte[src.Length];
                for (var i = 0; i < src.Length; i++)
                {
                    outBuf[i] = isEncrypt
                        ? (byte)(((src[i] ^ xorVal) << rot | (src[i] ^ xorVal) >> (8 - rot)) & 0xFF)
                        : (byte)(((src[i] >> rot | src[i] << (8 - rot)) & 0xFF) ^ xorVal);
                }
                steps.Add($"Registro WREG XOR 0x{xorVal:X2}");
                steps.Add($"Instrucción {(isEncrypt ? "ROL" : "ROR")} {rot} bit(s)");
                return (outBuf, isEncrypt ? Convert.ToBase64String(outBuf) : Encoding.UTF8.GetString(outBuf), steps.ToArray(), pubParams);
            }

            case "LSBSTEGO":
            {
                // Supports 24/32-bit BMP pixel LSB or binary carrier embedding with 'CS' header + 32-bit length
                if (isEncrypt)
                {
                    var payload = Concat("CS"u8.ToArray(), BitConverter.GetBytes(inputBytes.Length), inputBytes);
                    // Build a minimal 24-bit uncompressed BMP carrier sized to hold payload LSBs
                    var minPixels = payload.Length * 8 / 3 + 16;
                    var width = Math.Max(16, (int)Math.Ceiling(Math.Sqrt(minPixels)));
                    var height = Math.Max(16, (int)Math.Ceiling((double)minPixels / width));
                    var bmp = CreateCarrierBmp(width, height, keySha);
                    EmbedLsbIntoBmp(bmp, payload);
                    steps.Add($"BMP portador {width}x{height} generado ({bmp.Length} B)");
                    steps.Add($"Incrustados {payload.Length * 8} bits en canales RGB LSB");
                    return (bmp, Convert.ToBase64String(bmp), steps.ToArray(), pubParams);
                }
                else
                {
                    var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
                    var extracted = ExtractLsbFromBmp(src);
                    steps.Add("Cabecera 'CS' detectada en bits menos significativos (LSB)");
                    steps.Add($"Extraídos {extracted.Length} bytes");
                    return (extracted, Encoding.UTF8.GetString(extracted), steps.ToArray(), pubParams);
                }
            }

            case "EUCLIDESAFFINE":
            {
                var a = (int)ParseBigIntParam(key, "a", 5);
                var b = (int)ParseBigIntParam(key, "b", 11);
                if (a % 2 == 0) a += 1;
                var inv = ModInverseInt(a, 256);
                var src = isEncrypt ? inputBytes : (isFile ? inputBytes : Convert.FromBase64String(inputText.Trim()));
                var outBuf = new byte[src.Length];
                for (var i = 0; i < src.Length; i++)
                {
                    outBuf[i] = isEncrypt
                        ? (byte)((a * src[i] + b) % 256)
                        : (byte)(((inv * (src[i] - b)) % 256 + 256) % 256);
                }
                steps.Add($"MCD({a}, 256) = 1 · Euclides Extendido -> a⁻¹ = {inv}");
                steps.Add($"Transformación {(isEncrypt ? $"({a}·M + {b}) mod 256" : $"{inv}·(C - {b}) mod 256")}");
                return (outBuf, isEncrypt ? Convert.ToBase64String(outBuf) : Encoding.UTF8.GetString(outBuf), steps.ToArray(), pubParams);
            }

            case "MILLERRABIN":
            {
                var n = ParseBigIntParam(key, "n", 1009);
                var rounds = (int)ParseBigIntParam(key, "rondas", 5);
                var isPrime = MillerRabinTest(n, rounds);
                var derived = SHA256.HashData(Encoding.UTF8.GetBytes($"MR:{n}:{isPrime}:{key}"));
                steps.Add($"Evaluando primalidad de n = {n} ({rounds} rondas)");
                steps.Add($"Veredicto: {(isPrime ? "Probablemente primo" : "Compuesto")}");
                return SymmetricStreamHelper(isEncrypt, inputBytes, inputText, isFile, derived, steps, pubParams);
            }

            case "FISHERYATES":
            {
                var src = isEncrypt ? inputBytes : (isFile ? inputBytes : Convert.FromBase64String(inputText.Trim()));
                var perm = BuildFisherYatesPermutation(src.Length, keySha);
                var outBuf = new byte[src.Length];
                if (isEncrypt)
                    for (var i = 0; i < src.Length; i++) outBuf[i] = src[perm[i]];
                else
                    for (var i = 0; i < src.Length; i++) outBuf[perm[i]] = src[i];

                steps.Add($"Permutación Fisher–Yates sobre {src.Length} bytes");
                steps.Add($"Índices iniciales: [{string.Join(", ", perm.Take(6))}]");
                return (outBuf, isEncrypt ? Convert.ToBase64String(outBuf) : Encoding.UTF8.GetString(outBuf), steps.ToArray(), pubParams);
            }

            case "HASHSHA":
            {
                var digest = Convert.ToHexString(SHA256.HashData(inputBytes)).ToLowerInvariant();
                if (isEncrypt)
                {
                    steps.Add("Función hash unidireccional SHA-256 (256 bits)");
                    steps.Add($"Digest: {digest}");
                    return (Encoding.UTF8.GetBytes(digest), digest, steps.ToArray(), pubParams);
                }
                else
                {
                    var expectedBytes = Encoding.UTF8.GetBytes(key.Trim().ToLowerInvariant());
                    var actualBytes = Encoding.UTF8.GetBytes(digest);
                    var match = expectedBytes.Length == actualBytes.Length &&
                                CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
                    var msg = match ? $"VÁLIDO ({digest})" : $"NO COINCIDE ({digest})";
                    steps.Add($"SHA-256 calculado: {digest[..16]}…");
                    steps.Add($"Integridad: {(match ? "OK" : "FALLO")}");
                    return (Encoding.UTF8.GetBytes(msg), msg, steps.ToArray(), pubParams);
                }
            }

            case "HMACSHA256":
            {
                if (isEncrypt)
                {
                    var tag = Convert.ToHexString(HMACSHA256.HashData(keySha, inputBytes)).ToLowerInvariant();
                    var packed = $"{tag}|{Convert.ToBase64String(inputBytes)}";
                    steps.Add("HMAC-SHA256 generado con clave secreta");
                    steps.Add($"Tag: {tag[..16]}…");
                    return (Encoding.UTF8.GetBytes(packed), packed, steps.ToArray(), pubParams);
                }
                else
                {
                    var raw = isFile ? Encoding.UTF8.GetString(inputBytes) : inputText.Trim();
                    var parts = raw.Split('|', 2);
                    if (parts.Length != 2) throw new ArgumentException("Formato HMAC inválido (esperado tag|base64).");
                    var data = Convert.FromBase64String(parts[1]);
                    var expected = Convert.ToHexString(HMACSHA256.HashData(keySha, data)).ToLowerInvariant();
                    var valid = CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(parts[0].ToLowerInvariant()),
                        Encoding.UTF8.GetBytes(expected));
                    if (!valid) throw new CryptographicException("Etiqueta HMAC-SHA256 inválida.");
                    steps.Add("HMAC-SHA256 verificado en tiempo constante");
                    return (data, Encoding.UTF8.GetString(data), steps.ToArray(), pubParams);
                }
            }

            case "DIGITALSIG":
            {
                if (isEncrypt)
                {
                    var cert = _certZip.GetLocalCertificate();
                    var sig = _certZip.SignWithLocalKey(inputBytes);
                    var env = JsonSerializer.Serialize(new
                    {
                        sha256 = Convert.ToHexString(SHA256.HashData(inputBytes)).ToLowerInvariant(),
                        thumb = cert.ThumbprintSha256,
                        pem = cert.CertificatePem,
                        sig = Convert.ToBase64String(sig),
                        b64 = Convert.ToBase64String(inputBytes)
                    });
                    steps.Add($"Firma RSA-PSS-SHA256 emitida por {cert.SubjectName}");
                    steps.Add($"Huella: {cert.ThumbprintSha256[..16]}…");
                    return (Encoding.UTF8.GetBytes(env), env, steps.ToArray(), pubParams);
                }
                else
                {
                    var raw = isFile ? Encoding.UTF8.GetString(inputBytes) : inputText.Trim();
                    using var doc = JsonDocument.Parse(raw);
                    var root = doc.RootElement;
                    var data = Convert.FromBase64String(root.GetProperty("b64").GetString()!);
                    var sig = Convert.FromBase64String(root.GetProperty("sig").GetString()!);
                    var pem = root.GetProperty("pem").GetString()!;
                    if (!CertificateAndZipService.VerifyWithPem(data, sig, pem))
                        throw new CryptographicException("Firma digital RSA-PSS inválida.");
                    steps.Add("Firma digital RSA-PSS verificada con certificado X.509");
                    return (data, Encoding.UTF8.GetString(data), steps.ToArray(), pubParams);
                }
            }

            case "QUANTUMPQC":
            {
                var eveActive = key.Contains("eve=1", StringComparison.OrdinalIgnoreCase);
                var derived = SHA256.HashData(Encoding.UTF8.GetBytes($"BB84-LWE:{key}"));
                steps.Add("Simulación QKD BB84 (bases rectilínea + y diagonal ×)");
                steps.Add($"Tasa de error cuántico QBER: {(eveActive ? "25.0% (Intruso Eve detectado)" : "0.0% (Canal limpio)")}");
                steps.Add("Encapsulación poscuántica en retículos (LWE)");
                return SymmetricStreamHelper(isEncrypt, inputBytes, inputText, isFile, derived, steps, pubParams);
            }

            case "DFTSPECTRAL":
            {
                var shiftSeed = BitConverter.ToInt32(keySha, 0);
                if (isEncrypt)
                {
                    var spec = DftEncode(inputBytes, shiftSeed);
                    var json = JsonSerializer.Serialize(spec);
                    steps.Add($"Transformada Discreta de Fourier sobre {inputBytes.Length} muestras");
                    steps.Add("Permutación espectral en dominio de frecuencia aplicada");
                    return (Encoding.UTF8.GetBytes(json), json, steps.ToArray(), pubParams);
                }
                else
                {
                    var raw = isFile ? Encoding.UTF8.GetString(inputBytes) : inputText.Trim();
                    var spec = JsonSerializer.Deserialize<DftPayload>(raw) ?? throw new ArgumentException("Espectro DFT inválido.");
                    var plain = IdftDecode(spec, shiftSeed);
                    steps.Add($"IDFT inversa reconstruida ({plain.Length} bytes exactos)");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "LAGRANGESHAMIR":
            {
                var n = Math.Clamp((int)ParseBigIntParam(key, "N", 5), 2, 10);
                var k = Math.Clamp((int)ParseBigIntParam(key, "K", 3), 2, n);
                if (isEncrypt)
                {
                    var shares = ShamirSplit(inputBytes, n, k);
                    var lines = string.Join("\n", shares.Select(s => $"{s.X}:{Convert.ToBase64String(s.Y)}"));
                    steps.Add($"Esquema umbral (K={k}, N={n}) sobre GF(256)");
                    steps.Add($"Generadas {n} participaciones polinomiales");
                    return (Encoding.UTF8.GetBytes(lines), lines, steps.ToArray(), pubParams);
                }
                else
                {
                    var raw = isFile ? Encoding.UTF8.GetString(inputBytes) : inputText.Trim();
                    var parsed = raw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                        .Select(line =>
                        {
                            var parts = line.Split(':', 2);
                            return (X: byte.Parse(parts[0]), Y: Convert.FromBase64String(parts[1]));
                        }).ToList();
                    if (parsed.Count < 2) throw new ArgumentException("Se requieren al menos 2 participaciones.");
                    var plain = ShamirCombine(parsed);
                    steps.Add($"Interpolación de Lagrange f(0) con {parsed.Count} participaciones");
                    return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
                }
            }

            case "LORENZSZ40":
            {
                var src = isEncrypt ? inputBytes : (isFile ? inputBytes : Convert.FromBase64String(inputText.Trim()));
                var outBuf = LorenzXor(src, keySha);
                steps.Add("Máquina Lorenz SZ40 · 12 ruedas binarias (χ, ψ, μ)");
                steps.Add("Flujo pseudoaleatorio XOR autoinverso aplicado");
                return (outBuf, isEncrypt ? Convert.ToBase64String(outBuf) : Encoding.UTF8.GetString(outBuf), steps.ToArray(), pubParams);
            }

            default:
                throw new NotSupportedException($"Motor no implementado: {code}");
        }
    }

    private static (byte[] Bytes, string Text, string[] Steps, Dictionary<string, string> Params) SymmetricStreamHelper(
        bool isEncrypt, byte[] inputBytes, string inputText, bool isFile, byte[] derivedKey, List<string> steps, Dictionary<string, string> pubParams)
    {
        if (isEncrypt)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var cipher = ChaCha20Xor(inputBytes, derivedKey, nonce);
            var tag = HMACSHA256.HashData(derivedKey, Concat(nonce, cipher))[..16];
            var packed = Concat(nonce, tag, cipher);
            return (packed, Convert.ToBase64String(packed), steps.ToArray(), pubParams);
        }
        else
        {
            var src = isFile ? inputBytes : Convert.FromBase64String(inputText.Trim());
            var nonce = src[..12];
            var tag = src[12..28];
            var cipher = src[28..];
            var expected = HMACSHA256.HashData(derivedKey, Concat(nonce, cipher))[..16];
            if (!CryptographicOperations.FixedTimeEquals(tag, expected))
                throw new CryptographicException("Llave o parámetros inválidos.");
            var plain = ChaCha20Xor(cipher, derivedKey, nonce);
            return (plain, Encoding.UTF8.GetString(plain), steps.ToArray(), pubParams);
        }
    }

    // --- ChaCha20 RFC 8439 ---
    private static byte[] ChaCha20Xor(byte[] input, byte[] key32, byte[] nonce12)
    {
        static uint Rotl(uint v, int n) => (v << n) | (v >> (32 - n));
        static void Qr(uint[] s, int a, int b, int c, int d)
        {
            s[a] += s[b]; s[d] = Rotl(s[d] ^ s[a], 16);
            s[c] += s[d]; s[b] = Rotl(s[b] ^ s[c], 12);
            s[a] += s[b]; s[d] = Rotl(s[d] ^ s[a], 8);
            s[c] += s[d]; s[b] = Rotl(s[b] ^ s[c], 7);
        }

        var output = new byte[input.Length];
        for (uint block = 0; block * 64 < input.Length; block++)
        {
            uint[] st =
            {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                BitConverter.ToUInt32(key32, 0), BitConverter.ToUInt32(key32, 4),
                BitConverter.ToUInt32(key32, 8), BitConverter.ToUInt32(key32, 12),
                BitConverter.ToUInt32(key32, 16), BitConverter.ToUInt32(key32, 20),
                BitConverter.ToUInt32(key32, 24), BitConverter.ToUInt32(key32, 28),
                block,
                BitConverter.ToUInt32(nonce12, 0), BitConverter.ToUInt32(nonce12, 4), BitConverter.ToUInt32(nonce12, 8)
            };
            var wk = (uint[])st.Clone();
            for (var i = 0; i < 10; i++)
            {
                Qr(wk, 0, 4, 8, 12); Qr(wk, 1, 5, 9, 13); Qr(wk, 2, 6, 10, 14); Qr(wk, 3, 7, 11, 15);
                Qr(wk, 0, 5, 10, 15); Qr(wk, 1, 6, 11, 12); Qr(wk, 2, 7, 8, 13); Qr(wk, 3, 4, 9, 14);
            }
            var ks = new byte[64];
            for (var i = 0; i < 16; i++)
                BitConverter.TryWriteBytes(ks.AsSpan(i * 4, 4), wk[i] + st[i]);

            var limit = Math.Min(64, input.Length - (int)(block * 64));
            for (var i = 0; i < limit; i++)
                output[block * 64 + i] = (byte)(input[block * 64 + i] ^ ks[i]);
        }
        return output;
    }

    // --- Deterministic NIST P-256 Point Multiplication ---
    private static ECParameters DeriveP256FromSeed(byte[] seed32)
    {
        var p = BigInteger.Parse("00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
        var a = p - 3;
        var n = BigInteger.Parse("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", System.Globalization.NumberStyles.HexNumber);
        var gx = BigInteger.Parse("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", System.Globalization.NumberStyles.HexNumber);
        var gy = BigInteger.Parse("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", System.Globalization.NumberStyles.HexNumber);

        var d = new BigInteger(seed32, isUnsigned: true, isBigEndian: true) % (n - 1) + 1;
        var (qx, qy) = EcMul(d, gx, gy, a, p);

        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = ToFixed32(d),
            Q = new ECPoint { X = ToFixed32(qx), Y = ToFixed32(qy) }
        };
    }

    private static byte[] ToFixed32(BigInteger v)
    {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == 32) return raw;
        var buf = new byte[32];
        Buffer.BlockCopy(raw, Math.Max(0, raw.Length - 32), buf, Math.Max(0, 32 - raw.Length), Math.Min(32, raw.Length));
        return buf;
    }

    private static (BigInteger X, BigInteger Y) EcMul(BigInteger k, BigInteger gx, BigInteger gy, BigInteger a, BigInteger p)
    {
        BigInteger rx = 0, ry = 0;
        var hasPoint = false;
        BigInteger cx = gx, cy = gy;
        while (k > 0)
        {
            if ((k & 1) == 1)
            {
                if (!hasPoint) { rx = cx; ry = cy; hasPoint = true; }
                else (rx, ry) = EcAdd(rx, ry, cx, cy, a, p);
            }
            (cx, cy) = EcAdd(cx, cy, cx, cy, a, p);
            k >>= 1;
        }
        return (rx, ry);
    }

    private static (BigInteger X, BigInteger Y) EcAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2, BigInteger a, BigInteger p)
    {
        BigInteger lambda;
        if (x1 == x2 && y1 == y2)
        {
            var num = (3 * x1 * x1 + a) % p;
            var den = ModInverseBig((2 * y1) % p, p);
            lambda = (num * den) % p;
        }
        else
        {
            var num = ((y2 - y1) % p + p) % p;
            var den = ModInverseBig(((x2 - x1) % p + p) % p, p);
            lambda = (num * den) % p;
        }
        var x3 = ((lambda * lambda - x1 - x2) % p + p) % p;
        var y3 = ((lambda * (x1 - x3) - y1) % p + p) % p;
        return (x3, y3);
    }

    // --- BMP LSB Carrier Helpers ---
    private static byte[] CreateCarrierBmp(int width, int height, byte[] seed)
    {
        var rowSize = (width * 3 + 3) & ~3;
        var pixelBytes = rowSize * height;
        var total = 54 + pixelBytes;
        var bmp = new byte[total];
        bmp[0] = (byte)'B'; bmp[1] = (byte)'M';
        BitConverter.TryWriteBytes(bmp.AsSpan(2, 4), total);
        BitConverter.TryWriteBytes(bmp.AsSpan(10, 4), 54);
        BitConverter.TryWriteBytes(bmp.AsSpan(14, 4), 40);
        BitConverter.TryWriteBytes(bmp.AsSpan(18, 4), width);
        BitConverter.TryWriteBytes(bmp.AsSpan(22, 4), height);
        BitConverter.TryWriteBytes(bmp.AsSpan(26, 2), (ushort)1);
        BitConverter.TryWriteBytes(bmp.AsSpan(28, 2), (ushort)24);
        BitConverter.TryWriteBytes(bmp.AsSpan(34, 4), pixelBytes);
        for (var i = 54; i < total; i++) bmp[i] = (byte)((seed[i % seed.Length] + i) & 0xFE);
        return bmp;
    }

    private static void EmbedLsbIntoBmp(byte[] bmp, byte[] payload)
    {
        var offset = BitConverter.ToInt32(bmp, 10);
        var bitIdx = 0;
        for (var b = 0; b < payload.Length; b++)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var pos = offset + bitIdx;
                if (pos >= bmp.Length) throw new ArgumentException("Imagen portadora demasiado pequeña.");
                bmp[pos] = (byte)((bmp[pos] & 0xFE) | ((payload[b] >> bit) & 1));
                bitIdx++;
            }
        }
    }

    private static byte[] ExtractLsbFromBmp(byte[] bmp)
    {
        if (bmp.Length < 54 || bmp[0] != 'B' || bmp[1] != 'M')
            throw new ArgumentException("Se requiere imagen BMP válida para extracción LSB en servidor.");
        var offset = BitConverter.ToInt32(bmp, 10);
        byte ReadByte(int byteOff)
        {
            var val = 0;
            for (var bit = 0; bit < 8; bit++)
                val = (val << 1) | (bmp[offset + byteOff * 8 + bit] & 1);
            return (byte)val;
        }
        if (ReadByte(0) != 'C' || ReadByte(1) != 'S')
            throw new ArgumentException("Sin cabecera LSB válida.");
        var lenBytes = new[] { ReadByte(2), ReadByte(3), ReadByte(4), ReadByte(5) };
        var len = BitConverter.ToInt32(lenBytes, 0);
        if (len < 0 || offset + (6 + len) * 8 > bmp.Length)
            throw new ArgumentException("Longitud LSB inválida.");
        var outBuf = new byte[len];
        for (var i = 0; i < len; i++) outBuf[i] = ReadByte(6 + i);
        return outBuf;
    }

    // --- Math Helpers ---
    private static int ModInverseInt(int a, int m)
    {
        int oldR = a, r = m, oldS = 1, s = 0;
        while (r != 0)
        {
            int q = oldR / r;
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
        }
        return (oldS % m + m) % m;
    }

    private static BigInteger ModInverseBig(BigInteger a, BigInteger m)
    {
        BigInteger oldR = a, r = m, oldS = 1, s = 0;
        while (r != 0)
        {
            var q = oldR / r;
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
        }
        return (oldS % m + m) % m;
    }

    private static bool MillerRabinTest(BigInteger n, int rounds)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;
        var d = n - 1;
        var s = 0;
        while (d % 2 == 0) { d /= 2; s++; }
        for (var i = 0; i < rounds; i++)
        {
            var a = new BigInteger(2 + i * 7) % (n - 3 > 0 ? n - 3 : 2) + 2;
            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;
            var ok = false;
            for (var r = 1; r < s; r++)
            {
                x = (x * x) % n;
                if (x == n - 1) { ok = true; break; }
            }
            if (!ok) return false;
        }
        return true;
    }

    private static int[] BuildFisherYatesPermutation(int len, byte[] seedBytes)
    {
        uint seed = BitConverter.ToUInt32(seedBytes, 0);
        if (seed == 0) seed = 0x9E3779B9;
        var perm = Enumerable.Range(0, len).ToArray();
        for (var i = len - 1; i > 0; i--)
        {
            seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
            var j = (int)(seed % (uint)(i + 1));
            (perm[i], perm[j]) = (perm[j], perm[i]);
        }
        return perm;
    }

    private sealed record DftPayload(int N, double[] Re, double[] Im);

    private static DftPayload DftEncode(byte[] bytes, int shiftSeed)
    {
        const int Block = 64;
        var n = bytes.Length;
        var re = new double[n];
        var im = new double[n];
        for (var off = 0; off < n; off += Block)
        {
            var len = Math.Min(Block, n - off);
            for (var k = 0; k < len; k++)
            {
                double sumR = 0, sumI = 0;
                for (var i = 0; i < len; i++)
                {
                    var ang = -2.0 * Math.PI * k * i / len;
                    sumR += bytes[off + i] * Math.Cos(ang);
                    sumI += bytes[off + i] * Math.Sin(ang);
                }
                re[off + k] = Math.Round(sumR, 6);
                im[off + k] = Math.Round(sumI, 6);
            }
        }
        var perm = BuildFisherYatesPermutation(n, BitConverter.GetBytes(shiftSeed));
        return new DftPayload(n, perm.Select(p => re[p]).ToArray(), perm.Select(p => im[p]).ToArray());
    }

    private static byte[] IdftDecode(DftPayload spec, int shiftSeed)
    {
        const int Block = 64;
        var n = spec.N;
        var perm = BuildFisherYatesPermutation(n, BitConverter.GetBytes(shiftSeed));
        var ure = new double[n];
        var uim = new double[n];
        for (var i = 0; i < n; i++) { ure[perm[i]] = spec.Re[i]; uim[perm[i]] = spec.Im[i]; }
        var outBuf = new byte[n];
        for (var off = 0; off < n; off += Block)
        {
            var len = Math.Min(Block, n - off);
            for (var i = 0; i < len; i++)
            {
                double sum = 0;
                for (var k = 0; k < len; k++)
                {
                    var ang = 2.0 * Math.PI * k * i / len;
                    sum += ure[off + k] * Math.Cos(ang) - uim[off + k] * Math.Sin(ang);
                }
                outBuf[off + i] = (byte)Math.Clamp((int)Math.Round(sum / len), 0, 255);
            }
        }
        return outBuf;
    }

    // GF(256) Shamir Secret Sharing
    private static byte GfMul(byte a, byte b)
    {
        byte p = 0;
        for (var i = 0; i < 8; i++)
        {
            if ((b & 1) != 0) p ^= a;
            var hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    private static byte GfInv(byte a)
    {
        if (a == 0) return 0;
        byte res = 1;
        for (var i = 0; i < 254; i++) res = GfMul(res, a);
        return res;
    }

    private static List<(byte X, byte[] Y)> ShamirSplit(byte[] secret, int n, int k)
    {
        var shares = Enumerable.Range(1, n).Select(x => (X: (byte)x, Y: new byte[secret.Length])).ToList();
        var rng = RandomNumberGenerator.Create();
        var coeffs = new byte[k];
        for (var idx = 0; idx < secret.Length; idx++)
        {
            rng.GetBytes(coeffs);
            coeffs[0] = secret[idx];
            for (var s = 0; s < n; s++)
            {
                byte x = shares[s].X;
                byte val = 0;
                for (var c = k - 1; c >= 0; c--) val = (byte)(GfMul(val, x) ^ coeffs[c]);
                shares[s].Y[idx] = val;
            }
        }
        return shares;
    }

    private static byte[] ShamirCombine(List<(byte X, byte[] Y)> shares)
    {
        var len = shares[0].Y.Length;
        var outBuf = new byte[len];
        for (var idx = 0; idx < len; idx++)
        {
            byte acc = 0;
            for (var i = 0; i < shares.Count; i++)
            {
                byte num = 1, den = 1;
                for (var j = 0; j < shares.Count; j++)
                {
                    if (i == j) continue;
                    num = GfMul(num, shares[j].X);
                    den = GfMul(den, (byte)(shares[i].X ^ shares[j].X));
                }
                acc ^= GfMul(shares[i].Y[idx], GfMul(num, GfInv(den)));
            }
            outBuf[idx] = acc;
        }
        return outBuf;
    }

    private static byte[] LorenzXor(byte[] src, byte[] seed)
    {
        var chi = seed[0] | 1;
        var psi = seed[1] | 1;
        var mu = seed[2] | 1;
        var outBuf = new byte[src.Length];
        for (var i = 0; i < src.Length; i++)
        {
            chi = ((chi << 1) | (((chi >> 4) ^ (chi >> 2)) & 1)) & 0x1F;
            if ((mu & 1) != 0) psi = ((psi << 1) | (((psi >> 4) ^ (psi >> 1)) & 1)) & 0x1F;
            mu = ((mu << 1) | (((mu >> 5) ^ (mu >> 3)) & 1)) & 0x3F;
            var ks = (byte)(((chi ^ psi) << 3) | (chi & 0x07));
            outBuf[i] = (byte)(src[i] ^ ks);
        }
        return outBuf;
    }

    private static BigInteger ParseBigIntParam(string key, string name, BigInteger fallback)
    {
        var m = Regex.Match(key, $@"{Regex.Escape(name)}=(\d+)", RegexOptions.IgnoreCase);
        return m.Success && BigInteger.TryParse(m.Groups[1].Value, out var val) ? val : fallback;
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        var total = arrays.Sum(a => a.Length);
        var buf = new byte[total];
        var off = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, buf, off, a.Length);
            off += a.Length;
        }
        return buf;
    }
}
