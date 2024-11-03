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

        // Create the signing key
        var keyBytes = Convert.FromBase64String(privateKey);
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(keyBytes, out _);
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
}

