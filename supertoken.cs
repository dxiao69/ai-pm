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
        // Remove the PEM header, footer, and newlines
        var pem = privateKey
            .Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "");

        // Decode the Base64 content
        byte[] privateKeyBytes = Convert.FromBase64String(pem);

        // Parse the RSA private key
        var rsa = DecodeRsaPrivateKey(privateKeyBytes);
        return rsa;
    }

    private static RSA DecodeRsaPrivateKey(byte[] privateKeyBytes)
    {
        // This is for .NET Framework; manually parse the ASN.1 DER-encoded private key if necessary.
        var rsa = new RSACryptoServiceProvider();
        
        // Use helper to import private key parameters
        var rsaParameters = DecodeRSAPrivateKeyParameters(privateKeyBytes);
        rsa.ImportParameters(rsaParameters);

        return rsa;
    }

    private static RSAParameters DecodeRSAPrivateKeyParameters(byte[] privateKeyBytes)
    {
        // Decode the ASN.1 format (PKCS#1 DER encoding) to extract RSA parameters
        // For simplicity, you may want to use a library like BouncyCastle for this
        throw new NotImplementedException("ASN.1 parsing required here.");
    }
}

