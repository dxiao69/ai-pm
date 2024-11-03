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
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey.ToCharArray());

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
}
