using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class SuperTokenUpdater
{
    public static string UpdateSuperToken(string privateKey, string thumbPrint, string clientId, string link)
    {
        // Convert the thumbprint to a byte array
        var certOctets = Enumerable.Range(0, thumbPrint.Length / 2)
                                   .Select(i => Convert.ToByte(thumbPrint.Substring(i * 2, 2), 16))
                                   .ToArray();

        string x5t;
        using (var certBuffer = new SHA1Managed())
        {
            var hash = certBuffer.ComputeHash(certOctets);
            x5t = Convert.ToBase64String(hash).Replace("=", "").Replace("+", "-").Replace("/", "_");
        }

        // Define the JWT payload
        var payload = new
        {
            aud = link,
            iss = clientId,
            sub = clientId
        };

        // Create the signing key
        var keyBytes = Convert.FromBase64String(privateKey);
        var securityKey = new RsaSecurityKey(new RSAParameters
        {
            Modulus = keyBytes, 
            Exponent = new byte[] { 1, 0, 1 } // Typically exponent for RSA keys in .NET
        })
        {
            KeyId = thumbPrint
        };

        // Create the signing credentials
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        // Create the JWT header and add custom headers
        var header = new JwtHeader(signingCredentials)
        {
            { "kid", thumbPrint },
            { "x5t", x5t },
            { "alg", "RS256" },
            { "typ", "JWT" }
        };

        // Create the JWT token
        var jwtToken = new JwtSecurityToken(header, new JwtPayload(payload));
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(jwtToken);
    }
}



using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Linq;

public class SuperTokenUpdater
{
    public static string UpdateSuperToken(string privateKey, string thumbPrint, string clientId, string link)
    {
        // Convert the thumbprint to a byte array
        var certOctets = Enumerable.Range(0, thumbPrint.Length / 2)
                                   .Select(i => Convert.ToByte(thumbPrint.Substring(i * 2, 2), 16))
                                   .ToArray();

        string x5t;
        using (var sha1 = SHA1.Create())
        {
            var hash = sha1.ComputeHash(certOctets);
            x5t = Convert.ToBase64String(hash).Replace("=", "").Replace("+", "-").Replace("/", "_");
        }

        // Initialize RSA key
        RSA rsa = CreateRsaFromPrivateKey(privateKey);
        var securityKey = new RsaSecurityKey(rsa) { KeyId = thumbPrint };

        // Define the JWT payload
        var payload = new JwtPayload
        {
            { "aud", link },
            { "iss", clientId },
            { "sub", clientId },
            { "exp", DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds() }
        };

        // Create the signing credentials
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        // Create the JWT header with custom headers
        var header = new JwtHeader(signingCredentials)
        {
            { "kid", thumbPrint },
            { "x5t", x5t },
            { "alg", "RS256" },
            { "typ", "JWT" }
        };

        // Create the JWT token
        var jwtToken = new JwtSecurityToken(header, payload);
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(jwtToken);
    }

    private static RSA CreateRsaFromPrivateKey(string privateKey)
    {
        // Decode from base64 if needed
        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);

        var rsa = RSA.Create();
        
        try
        {
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _); // .NET Core or .NET 5+
        }
        catch
        {
            // For .NET Framework or older .NET versions, manually load the key
            var rsaParameters = new RSAParameters();
            
            // You can parse and set the RSA parameters manually here if in another format,
            // or use libraries like BouncyCastle for PEM decoding in .NET Framework

            rsa.ImportParameters(rsaParameters);
        }

        return rsa;
    }
}


------------------------------------

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;

public class SuperTokenUpdater
{
    public static string UpdateSuperToken(string privateKey, string thumbPrint, string clientId, string link)
    {
        // Convert the thumbprint to a byte array
        var certOctets = Enumerable.Range(0, thumbPrint.Length / 2)
                                   .Select(i => Convert.ToByte(thumbPrint.Substring(i * 2, 2), 16))
                                   .ToArray();

        string x5t;
        using (var sha1 = SHA1.Create())
        {
            var hash = sha1.ComputeHash(certOctets);
            x5t = Convert.ToBase64String(hash).Replace("=", "").Replace("+", "-").Replace("/", "_");
        }

        // Initialize RSA key using BouncyCastle
        RSA rsa = CreateRsaFromPrivateKey(privateKey);
        var securityKey = new RsaSecurityKey(rsa) { KeyId = thumbPrint };

        // Define the JWT payload
        var payload = new JwtPayload
        {
            { "aud", link },
            { "iss", clientId },
            { "sub", clientId },
            { "exp", DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds() }
        };

        // Create the signing credentials
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        // Create the JWT header with custom headers
        var header = new JwtHeader(signingCredentials)
        {
            { "kid", thumbPrint },
            { "x5t", x5t },
            { "alg", "RS256" },
            { "typ", "JWT" }
        };

        // Create the JWT token
        var jwtToken = new JwtSecurityToken(header, payload);
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(jwtToken);
    }

    private static RSA CreateRsaFromPrivateKey(string privateKey)
    {
        // Clean up the PEM format
        privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "")
                               .Replace("-----END PRIVATE KEY-----", "")
                               .Replace("\n", "")
                               .Replace("\r", "");

        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);

        // Decode the RSA parameters using BouncyCastle
        RSAParameters rsaParams = DecodeRsaPrivateKeyParameters(privateKeyBytes);

        // Create RSA object and import parameters
        var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        return rsa;
    }

    private static RSAParameters DecodeRsaPrivateKeyParameters(byte[] privateKeyBytes)
    {
        using (var memStream = new MemoryStream(privateKeyBytes))
        using (var reader = new StreamReader(memStream))
        {
            var pemReader = new PemReader(reader);
            if (!(pemReader.ReadObject() is RsaPrivateCrtKeyParameters rsaPrivateKey))
                throw new ArgumentException("Invalid private key format.");

            return new RSAParameters
            {
                Modulus = rsaPrivateKey.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaPrivateKey.PublicExponent.ToByteArrayUnsigned(),
                D = rsaPrivateKey.Exponent.ToByteArrayUnsigned(),
                P = rsaPrivateKey.P.ToByteArrayUnsigned(),
                Q = rsaPrivateKey.Q.ToByteArrayUnsigned(),
                DP = rsaPrivateKey.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaPrivateKey.QInv.ToByteArrayUnsigned()
            };
        }
    }
}


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

public class AzureOAuthHelper
{
    private readonly string clientId;
    private readonly string tenantId;
    private readonly string privateKey;
    private readonly string thumbprint;

    public AzureOAuthHelper(string clientId, string tenantId, string privateKey, string thumbprint)
    {
        this.clientId = clientId;
        this.tenantId = tenantId;
        this.privateKey = privateKey;
        this.thumbprint = thumbprint;
    }

    public async Task<string> RedeemAuthorizationCodeAsync(string authorizationCode, string redirectUri, string scope)
    {
        string tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

        // Create client assertion
        var clientAssertion = GenerateClientAssertion();

        using (var client = new HttpClient())
        {
            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("code", authorizationCode),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion", clientAssertion)
            });

            request.Content = content;

            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse; // This will include the access token
        }
    }

    private string GenerateClientAssertion()
    {
        var rsa = CreateRsaProviderFromPrivateKey(privateKey);

        var securityKey = new RsaSecurityKey(rsa) { KeyId = thumbprint };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateJwtSecurityToken(
            issuer: clientId,
            audience: $"https://login.microsoftonline.com/{tenantId}/v2.0",
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: credentials);

        return handler.WriteToken(token);
    }

    private static RSA CreateRsaProviderFromPrivateKey(string privateKeyPem)
    {
        var rsaParameters = GetRSAParametersFromPrivateKey(privateKeyPem);
        var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParameters);
        return rsa;
    }

    private static RSAParameters GetRSAParametersFromPrivateKey(string privateKeyPem)
    {
        // Strip the headers from the PEM file
        var privateKeyBytes = Convert.FromBase64String(
            privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                         .Replace("-----END RSA PRIVATE KEY-----", "")
                         .Replace("\n", "")
                         .Replace("\r", ""));

        using (var mem = new System.IO.MemoryStream(privateKeyBytes))
        using (var reader = new BinaryReader(mem))
        {
            byte[] twoBytes = reader.ReadBytes(2);
            if (twoBytes[0] == 0x30 && twoBytes[1] == 0x82)
            {
                reader.ReadInt16(); // Skip the version marker
            }

            var rsaParameters = new RSAParameters
            {
                Modulus = ReadInteger(reader),
                Exponent = ReadInteger(reader),
                D = ReadInteger(reader),
                P = ReadInteger(reader),
                Q = ReadInteger(reader),
                DP = ReadInteger(reader),
                DQ = ReadInteger(reader),
                InverseQ = ReadInteger(reader)
            };

            return rsaParameters;
        }
    }

    private static byte[] ReadInteger(BinaryReader reader)
    {
        if (reader.ReadByte() != 0x02)
            throw new InvalidOperationException("Expected an ASN.1 integer");

        int count = reader.ReadByte();
        if (count == 0x81)
            count = reader.ReadByte();
        else if (count == 0x82)
            count = 256 * reader.ReadByte() + reader.ReadByte();

        byte[] integer = reader.ReadBytes(count);
        if (integer[0] == 0x00)
        {
            byte[] tmp = new byte[integer.Length - 1];
            Array.Copy(integer, 1, tmp, 0, tmp.Length);
            integer = tmp;
        }
        return integer;
    }
}

================================

    private static RSAParameters GetRSAParametersFromPrivateKey(string privateKeyPem)
{
    var privateKeyBytes = Convert.FromBase64String(
        privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                     .Replace("-----END RSA PRIVATE KEY-----", "")
                     .Replace("\n", "")
                     .Replace("\r", ""));

    // Check for the PKCS#1 format
    if (privateKeyBytes[0] != 0x30) // ASN.1 sequence
    {
        throw new InvalidOperationException("Invalid private key format.");
    }

    using (var ms = new System.IO.MemoryStream(privateKeyBytes))
    using (var reader = new BinaryReader(ms))
    {
        reader.ReadByte(); // Sequence
        reader.ReadUInt16(); // Length

        var version = reader.ReadByte(); // Version
        if (version != 0x00) throw new InvalidOperationException("Invalid version.");

        RSAParameters parameters = new RSAParameters();

        parameters.Modulus = ReadInteger(reader);
        parameters.Exponent = ReadInteger(reader);
        parameters.D = ReadInteger(reader);
        parameters.P = ReadInteger(reader);
        parameters.Q = ReadInteger(reader);
        parameters.DP = ReadInteger(reader);
        parameters.DQ = ReadInteger(reader);
        parameters.InverseQ = ReadInteger(reader);

        return parameters;
    }
}

private static byte[] ReadInteger(BinaryReader reader)
{
    byte firstByte = reader.ReadByte();
    if (firstByte != 0x02)
        throw new InvalidOperationException("Expected an ASN.1 integer");

    int length = reader.ReadByte();
    if (length == 0x81)
        length = reader.ReadByte();
    else if (length == 0x82)
        length = (reader.ReadByte() << 8) + reader.ReadByte();

    byte[] integer = reader.ReadBytes(length);
    
    // Remove leading zero byte, if present
    if (integer.Length > 0 && integer[0] == 0)
    {
        byte[] tmp = new byte[integer.Length - 1];
        Array.Copy(integer, 1, tmp, 0, tmp.Length);
        integer = tmp;
    }
    
    return integer;
}



private static RSAParameters GetRSAParametersFromPrivateKey(string privateKeyPem)
{
    var privateKeyBytes = Convert.FromBase64String(
        privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "")
                     .Replace("-----END PRIVATE KEY-----", "")
                     .Replace("\n", "")
                     .Replace("\r", ""));

    // Check for PKCS#8 format
    if (privateKeyBytes[0] != 0x30) // ASN.1 sequence
    {
        throw new InvalidOperationException("Invalid private key format.");
    }

    using (var ms = new System.IO.MemoryStream(privateKeyBytes))
    using (var reader = new BinaryReader(ms))
    {
        // Skip the version and read to the next sequence
        reader.ReadByte(); // Sequence
        reader.ReadUInt16(); // Length
        reader.ReadByte(); // Version

        // Read the Algorithm Identifier
        reader.ReadByte(); // Sequence
        reader.ReadUInt16(); // Length
        reader.ReadByte(); // OID Identifier
        reader.ReadByte(); // Length of the OID

        // Skip OID (usually for the RSA algorithm)
        while (reader.PeekChar() != -1) reader.ReadByte(); // Skip to the next section

        // Now we should be at the private key data, which is another sequence
        reader.ReadByte(); // Sequence
        reader.ReadUInt16(); // Length

        // Read the private key integers
        RSAParameters parameters = new RSAParameters
        {
            Modulus = ReadInteger(reader),  // Usually not present in PKCS#8, need to derive from the private key
            Exponent = ReadInteger(reader),  // Not present
            D = ReadInteger(reader),
            P = ReadInteger(reader),
            Q = ReadInteger(reader),
            DP = ReadInteger(reader),
            DQ = ReadInteger(reader),
            InverseQ = ReadInteger(reader)
        };

        return parameters;
    }
}


using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

private static RSAParameters GetRSAParametersFromPrivateKey(string privateKeyPem)
{
    using (var stringReader = new System.IO.StringReader(privateKeyPem))
    {
        var pemReader = new PemReader(stringReader);
        var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

        return DotNetUtilities.ToRSAParameters(privateKey);
    }
}


using System;
using System.Linq;
using System.Security.Cryptography;

public static class X5tGenerator
{
    public static string GenerateX5t(string thumbPrintHex)
    {
        // Convert the hex string thumbprint to a byte array
        byte[] thumbPrintBytes = Enumerable.Range(0, thumbPrintHex.Length / 2)
                                           .Select(i => Convert.ToByte(thumbPrintHex.Substring(i * 2, 2), 16))
                                           .ToArray();

        // Compute SHA-1 hash of the thumbprint bytes
        using (var sha1 = SHA1.Create())
        {
            byte[] hashBytes = sha1.ComputeHash(thumbPrintBytes);

            // Convert the hash to base64 and replace URL-unsafe characters
            return Convert.ToBase64String(hashBytes)
                          .Replace("=", "") // Remove padding
                          .Replace("+", "-") // Make URL-safe
                          .Replace("/", "_"); // Make URL-safe
        }
    }
}

