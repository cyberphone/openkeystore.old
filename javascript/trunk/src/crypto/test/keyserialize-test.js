function deserializeTest (x509_spki, jcs_pk)
{
    if (!org.webpki.util.ByteArray.equals (x509_spki, org.webpki.json.JSONParser.parse (jcs_pk).getPublicKey ()))
    {
        throw "Didn't match: ";
    }
}

var p256_key =
'{\
  "PublicKey": \
    {\
      "EC": \
        {\
          "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",\
          "X": "GRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOU",\
          "Y": "isxpqxSx6AAEmZfgL5HevS67ejfm_4HcsB883TUaccs"\
        }\
    }\
}';

var p256_key_xml =
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "urn:oid:1.2.840.10045.3.1.7",\
            "X": "GRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOU",\
            "Y": "isxpqxSx6AAEmZfgL5HevS67ejfm_4HcsB883TUaccs"\
          }\
      }\
  }';

var p256_key_spki = org.webpki.util.Base64URL.decode ('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw');

var rsa_2048_key = 
'{\
    "@context": "http://keys/test",\
    "PublicKey": \
      {\
        "RSA": \
          {\
            "Modulus": "6mct2A1crFheV3fiMvXzwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn\
8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3\
rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJTC_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3\
ltPOjDgADLKw",\
            "Exponent": "AQAB"\
          }\
      }\
  }';

var rsa_2048_key_spki = org.webpki.util.Base64URL.decode ('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mct2A1crFheV3fiMvX\
zwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4\
BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJT\
C_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3ltPOjDgADLKwIDAQAB');

// console.debug (org.webpki.util.ByteArray.toHex (p256_key_spki));
console.debug (org.webpki.util.ByteArray.toHex (rsa_2048_key_spki));

deserializeTest (p256_key_spki, p256_key);
deserializeTest (p256_key_spki, p256_key_xml);

deserializeTest (rsa_2048_key_spki, rsa_2048_key);

console.debug ("Key serializing tests successful!");


