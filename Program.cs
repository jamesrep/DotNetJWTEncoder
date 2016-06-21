/// More security related tools: www.wallparse.com
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Globalization;

/// <summary>
/// A simple tool to create Json Web Tokens
/// 
/// Example:
///  jwtencoder.exe --claimfile C:\src\JWTEncoder\bin\Debug\claims.txt --kid AAAA --x5t BBBB --certfile c:\cert3.pfx
/// 
/// Creating certificates for tests using OpenSSL:
/// 
/// 1. Create certificate
/// openssl req -x509 -newkey rsa:2048 -keyout key2.pem -out cert.pem -days 3650
/// 
/// 2. Convert to PFX
/// openssl pkcs12 -export -out cert2.pfx -inkey key2.pem -in cert.pem -certfile cert.pem
/// 
/// 3. I dont really know why... but I had to import the certificate into personal cert store and then export it... maybe I forgot some parameter.
/// 
/// More security related tools: www.wallparse.com
/// 
/// </summary>
namespace DotNetJWTEncoder
{
    class Program
    {
        /// <summary>
        /// The only header we need.
        /// </summary>
        static string STR_HEADER =
            "{{ " +
             "\"alg\": \"RS256\", " +
             "\"kid\": \"{0}\", " +
             "\"typ\": \"JWT\", " +
             "\"x5t\": \"{1}\" " +
            "}}";

        static string STR_HASHTYPE = "SHA256";

        static readonly DateTime DT_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Returns the crypto service provider from certificate
        /// </summary>
        private static RSACryptoServiceProvider getProviderFromCert(X509Certificate2 certificate)
        {
            var rsa = (RSACryptoServiceProvider)certificate.PrivateKey;
            var cspParam = new CspParameters
            {
                KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName,
                KeyNumber = (int)KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore

            };

            RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider(cspParam) { PersistKeyInCsp = false };

            return cryptoServiceProvider;
        }

        /// <summary>
        /// Create JWT and sign with private key.
        /// </summary>
        /// <returns>The JWT string</returns>
        private static string createJWT(string strCertificateFilename, string strCertificatePass, string strSerializedHeader, string strSerializedClaim) 
        {
            // 1. Load the certificate
            const X509KeyStorageFlags certFlags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable;
            X509Certificate2 certificate = new X509Certificate2(strCertificateFilename, strCertificatePass, certFlags);

            // 2. Convert Json header to b64
            byte [] headerBytes = Encoding.ASCII.GetBytes(strSerializedHeader);
            string strEncodedHeader = System.Convert.ToBase64String(headerBytes);

            // 3. Convert Json claimset to b64
            byte[] claimsetBytes = Encoding.ASCII.GetBytes(strSerializedClaim);
            string strEncodedClaims = System.Convert.ToBase64String(claimsetBytes); 

            // 4. Get input that should be signed
            string strHeaderAndClaim = string.Format("{0}.{1}", strEncodedHeader, strEncodedClaims);
            byte [] btsHeaderAndClaim = Encoding.ASCII.GetBytes(strHeaderAndClaim);

            // 5. Sign the JWT
            RSACryptoServiceProvider csp = getProviderFromCert(certificate);
            byte [] signatureBytes = csp.SignData(btsHeaderAndClaim, STR_HASHTYPE);
            string signatureEncoded = System.Convert.ToBase64String(signatureBytes);

            // 6. Finally we concat all the strings to get jwt and return the result
            string strResult = string.Format("{0}.{1}.{2}", strEncodedHeader, strEncodedClaims, signatureEncoded);

            return strResult;
        }



        /// <summary>
        /// Read claim from file
        /// </summary>
        /// <param name="strFile"></param>
        /// <returns></returns>
        static string getClaim(string strFile)
        {
            return System.IO.File.ReadAllText(strFile);
        }


        /// <summary>
        ///  Returns the unix-epoch
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        static string getEpoch(DateTime dt)
        {
            return ((int)dt.Subtract(DT_EPOCH).TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        static void printArgs()
        {
            Console.WriteLine("Example: ");
            Console.WriteLine("jwtencoder.exe --claimfile C:\\claims.txt --kid AAAA --x5t BBBB --certfile c:\\cert3.pfx");

            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("--claimfile <file containing json with claims>");
            Console.WriteLine("--headerfile <file containing json with header>");
            Console.WriteLine("--kid <kid if no header file>");
            Console.WriteLine("--x5t <x5t if no header file>");
            Console.WriteLine("--certfile <certificate file>");
            Console.WriteLine("--certpass <certificate password>");
            Console.WriteLine("--epoch <datetime of epoch-request (optional)>");
        }

        /// <summary>
        /// This is just a simple tool. There are no error handling etc. 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            string strClaimFile = null;
            string strKid = "A";
            string strX5t = "B";
            string strCertFile = null;
            string strCertPass = "james";
            string strHeaderfile = null;

            if(args.Length < 1)
            {
                printArgs();
                return;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if ((i+1) < args.Length)
                {
                    if (args[i] == "--claimfile")
                    {
                        strClaimFile = args[++i];
                    }
                    else if (args[i] == "--headerfile")
                    {
                        strHeaderfile = args[++i];
                    }
                    else if (args[i] == "--kid")
                    {
                        strKid = args[++i];
                    }
                    else if (args[i] == "--x5t")
                    {
                        strX5t = args[++i];
                    }
                    else if (args[i] == "--certfile")
                    {
                        strCertFile = args[++i];
                    }
                    else if (args[i] == "--certpass")
                    {
                        strCertPass = args[++i];
                    }
                    else if (args[i] == "--epoch")
                    {
                        DateTime dtEpoch = Convert.ToDateTime( args[++i]);
                        Console.WriteLine(getEpoch(dtEpoch));
                    }
                }
            }

            if (strClaimFile != null)
            {
                // 1. Get the header and claims
                string strHeader = null;

                if (strHeaderfile != null) { strHeader = getClaim(strHeaderfile); }
                else { strHeader = string.Format(STR_HEADER, strKid, strX5t); }

                string strClaim = getClaim(strClaimFile);

                // 2. Create the JWT and print it to stdout
                string strJWT = createJWT(strCertFile, strCertPass, strHeader, strClaim);

                Console.WriteLine(strJWT);
            }

        }
    }
}
