using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;

// A bare-bones .NET program creating a signed JSON document and then validating it.
// The program implements a subset of JCS (JSON Cleartext Signature).

class JCSDemo
{
    // JCS Arguments
    public const string EC_PUBLIC_KEY = "EC";
    public const string RSA_PUBLIC_KEY = "RSA";
    public const string SIGNATURE_VERSION_ID = "http://xmlns.webpki.org/jcs/v1";

    // JCS JSON properties
    public const string ALGORITHM_JSON = "algorithm";
    public const string CURVE_JSON = "curve";
    public const string E_JSON = "e";
    public const string EXTENSIONS_JSON = "extensions";
    public const string ISSUER_JSON = "issuer";
    public const string KEY_ID_JSON = "keyId";
    public const string N_JSON = "n";
    public const string PUBLIC_KEY_JSON = "publicKey";
    public const string SERIAL_NUMBER_JSON = "serialNumber";
    public const string SIGNATURE_JSON = "signature";
    public const string SIGNER_CERTIFICATE_JSON = "signerCertificate";
    public const string SUBJECT_JSON = "subject";
    public const string TYPE_JSON = "type";
    public const string PEM_URL_JSON = "pemUrl";
    public const string VALUE_JSON = "value";
    public const string VERSION_JSON = "version";
    public const string X_JSON = "x";
    public const string CERTIFICATE_PATH_JSON = "certificatePath";
    public const string Y_JSON = "y";

    // JCS/JOSE Algorithms
    public const string ES256_ALG = "ES256";
    public const string P_521_CRV = "P-521";

    static string base64urlencode(byte[] arg)
    {
        string s = Convert.ToBase64String(arg); // Regular base64 encoder
        s = s.Split('=')[0]; // Remove any trailing '='s
        s = s.Replace('+', '-'); // 62nd char of encoding
        s = s.Replace('/', '_'); // 63rd char of encoding
        return s;
    }

    static byte[] base64urldecode(string arg)
    {
        string s = arg;
        s = s.Replace('-', '+'); // 62nd char of encoding
        s = s.Replace('_', '/'); // 63rd char of encoding
        switch (s.Length % 4) // Pad with trailing '='s
        {
            case 0: break; // No pad chars in this case
            case 2: s += "=="; break; // Two pad chars
            case 3: s += "="; break; // One pad char
            default: throw new System.Exception(
              "Illegal base64url string!");
        }
        return Convert.FromBase64String(s); // Standard base64 decoder
    }

    public static string createJcs(ECDsaCng ecKey, Dictionary<String, Object> document)
    {
        // Add signature object
        Dictionary<String, Object> signature = new Dictionary<String, Object>();
        document[SIGNATURE_JSON] = signature;
        signature[ALGORITHM_JSON] = ES256_ALG;
        Dictionary<String, Object> publicKey = new Dictionary<String, Object>();
        signature[PUBLIC_KEY_JSON] = publicKey;
        publicKey[TYPE_JSON] = EC_PUBLIC_KEY;
        publicKey[CURVE_JSON] = P_521_CRV;
        byte[] rawKey = ecKey.Key.Export(CngKeyBlobFormat.EccPublicBlob);
        byte[] coordinate = new byte[66];
        Buffer.BlockCopy(rawKey, 8, coordinate, 0, 66);
        publicKey[X_JSON] = base64urlencode(coordinate);
        Buffer.BlockCopy(rawKey, 74, coordinate, 0, 66);
        publicKey[Y_JSON] = base64urlencode(coordinate);
        ecKey.HashAlgorithm = CngAlgorithm.Sha256;
        signature[VALUE_JSON] = base64urlencode(ecKey.SignData(Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(document))));
        return new JavaScriptSerializer().Serialize(document);
    }

    public static bool validateJcs(Dictionary<String, Object> document)
    {
        Dictionary<String, Object> signature = (Dictionary<String, Object>)document[SIGNATURE_JSON];
        Dictionary<String, Object> signatureClone = new Dictionary<String, Object>(signature);
        Dictionary<String, Object> publicKey = (Dictionary<String, Object>)signature[PUBLIC_KEY_JSON];
        if (!signature[ALGORITHM_JSON].Equals(ES256_ALG))
        {
            throw new ArgumentException("\"" + ES256_ALG + "\" expected");
        }
        if (!publicKey[TYPE_JSON].Equals(EC_PUBLIC_KEY))
        {
            throw new ArgumentException("\"" + EC_PUBLIC_KEY + "\" expected");
        }
        if (!publicKey[CURVE_JSON].Equals(P_521_CRV))
        {
            throw new ArgumentException("\"" + P_521_CRV + "\" expected");
        }
        byte[] rawKey = new byte[140]; rawKey[0] = 69; rawKey[1] = 67; rawKey[2] = 83; rawKey[3] = 53; rawKey[4] = 66;
        Buffer.BlockCopy(base64urldecode((string)publicKey[X_JSON]), 0, rawKey, 8, 66);
        Buffer.BlockCopy(base64urldecode((string)publicKey[Y_JSON]), 0, rawKey, 74, 66);

        // Normalization: Remove signature/value from the document
        signature.Remove(VALUE_JSON);

        // Normalization: The rest is what we consider signable
        byte[] data = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(document));

        // However, we don't want signature validation to modify the document!
        document[SIGNATURE_JSON] = signatureClone;
        using (ECDsaCng ecKey = new ECDsaCng(CngKey.Import(rawKey, CngKeyBlobFormat.EccPublicBlob)))
        {
            ecKey.HashAlgorithm = CngAlgorithm.Sha256;
            return ecKey.VerifyData(data, base64urldecode((string)signatureClone[VALUE_JSON]));
        }
    }

    public static void Main(string[] args)
    {
        // The JSON document to be signed
        Dictionary<String, Object> document = new Dictionary<String, Object>();
        document["now"] = "2015-01-17T10:20:03Z";
        document["intProperty"] = 612;

        // Use a P-521 ECDSA key for signing
        using (ECDsaCng ecKey = new ECDsaCng(521))
        {
            string json = createJcs(ecKey, document);
            Console.WriteLine("Signed JSON Document:\n" + json);
            Console.WriteLine("\nVerified=" + validateJcs(new JavaScriptSerializer().Deserialize<Dictionary<String, Object>>(json)));
        }
    }
}
