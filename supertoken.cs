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


