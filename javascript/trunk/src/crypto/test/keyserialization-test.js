function deserializeTest (spki, jcs)
{
    var spki_bin = org.webpki.util.Base64URL.decode (spki);
    /* JSONObjectReader */var or = org.webpki.json.JSONParser.parse (jcs);
    /* PublicKey */var public_key = or.getPublicKey ();
    if (!org.webpki.util.ByteArray.equals (public_key, spki_bin))
    {
        throw "Reading JCS key failed";
    }
    /* JSONObjectWriter */var ow = new org.webpki.json.JSONObjectWriter ().setXMLDSigECCurveOption (jcs.indexOf ("urn:oid") > 0);
    if (ow.setPublicKey (spki_bin).serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED)
                 != 
        new org.webpki.json.JSONObjectWriter (or).serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED))
    {
        throw "Writing Public key failed";
    }
    /* JSONObjectReader */var pub_key_object = or.getObject (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON);
    /* boolean */var rsa_flag = pub_key_object.hasProperty (org.webpki.json.JSONSignatureDecoder.RSA_JSON);
    pub_key_object = pub_key_object.getObject (rsa_flag ? org.webpki.json.JSONSignatureDecoder.RSA_JSON : org.webpki.json.JSONSignatureDecoder.EC_JSON);
    console.debug ("Serializing " + (rsa_flag ? "RSA" : "EC curve=" + pub_key_object.getString (org.webpki.json.JSONSignatureDecoder.NAMED_CURVE_JSON)));
    /* String */var key_parm = rsa_flag ? org.webpki.json.JSONSignatureDecoder.MODULUS_JSON : org.webpki.json.JSONSignatureDecoder.Y_JSON;
    var parm_bytes = org.webpki.util.ByteArray.add ([0], pub_key_object.getBinary (key_parm));
    /* JSONObjectWriter */var updated_pub_key_object = new org.webpki.json.JSONObjectWriter (pub_key_object);
    updated_pub_key_object.setupForRewrite (key_parm);
    updated_pub_key_object.setBinary (key_parm, parm_bytes);
    var failed = true;
    try
    {
        org.webpki.json.JSONParser.parse (new org.webpki.json.JSONObjectWriter (or).serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT)).getPublicKey ();
    }
    catch (err)
    {
        var failed = false;
    }
    if (failed) throw "Should have failed";
}

function certReader (cert_in_b64)
{
    var cert_data = new org.webpki.crypto.decodeX509Certificate (org.webpki.util.Base64URL.decode (cert_in_b64));
    console.debug ("Certificate with SN=" + cert_data.serial_number.toString () + "\n" +
            new org.webpki.json.JSONObjectWriter ().setPublicKey (cert_data.public_key).serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
    var cert = "" + AntCrypto.getX509CertificateParams (cert_in_b64);
    var json_cert = cert_data.issuer + '\n' + cert_data.subject + '\n' + cert_data.serial_number.toString ();
    if (cert != json_cert)
    {
        throw "Cert err\n" + cert + "\n" + json_cert;
    }
    else
    {
        console.debug ("DN:\n" + json_cert);
    }
}

function dnTest (unicode_argument)
{
    var utf8 = org.webpki.util.Base64URL.decode ("" + AntCrypto.convertToUTF8 (unicode_argument));
    var asn1 = 
                new org.webpki.asn1.ASN1Object
                  (
                    org.webpki.asn1.TAGS.SEQUENCE,
                    new org.webpki.asn1.ASN1Object 
                      (
                        org.webpki.asn1.TAGS.SET,
                        new org.webpki.asn1.ASN1Object 
                          (
                            org.webpki.asn1.TAGS.SEQUENCE,
                            new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.OID,  new Uint8Array ([0x55, 0x04, 0x03]))
                          )
                        .addComponent (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.UTF8STRING, utf8))
                      )
                  )
            .encode ();
    var java_dn =  "" +  AntCrypto.getDistinguishedName (org.webpki.util.Base64URL.encode (asn1));

    var json_dn = org.webpki.crypto.getDistinguishedName (new org.webpki.asn1.ParsedASN1Sequence (asn1));
    if (!java_dn.equals (json_dn))
    {
        throw "DN fail " + json_dn + " " + java_dn;
    }

//    AntCrypto.getDistinguishedName (org.webpki.util.Base64URL.encode (utf8)); 
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

var p256_key_spki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw';

var rsa_2048_key = 
'{\
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

var rsa_2048_key_spki = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mct2A1crFheV3fiMvX\
zwFJgR6fWnBRyg6X0P_uTQOlll1orTqd6a0QTTjnm1XlM5XF8g5SyqhIO4kLUmvJvwEHaXHHkbn8N4gHzhbPA7FHVdCt37W5jduUVWHlBVoXIbGaLrCUj4\
BCDmXImhOHxbhRvyiY2XWcDFAGt_60IzLAnPUof2Rv-aPNYJY6qa0yvnJmQp4yNPsIpHYpj9Sa3rctEC2OELZy-HTlDBVyzEYwnmDXtvhjoPEaUZUyHaJT\
C_LZMOTsgJqDT8mOvHyZpLH_f7u55mXDBoXF0iG9sikiRVndkJ18wZmNRow2UmK3QB6G2kUYxt3ltPOjDgADLKwIDAQAB';

var p521_key =
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",\
            "X": "AQggHPZ-De2Tq_7U7v8ADpjyouKk6eV97Lujt9NdIcZgWI_cyOLv9HZulGWtC7I3X73ABE-rx95hAKbxiqQ1q0bA",\
            "Y": "_nJhyQ20ca7Nn0Zvyiq54FfCAblGK7kuduFBTPkxv9eOjiaeGp7V_f3qV1kxS_Il2LY7Tc5l2GSlW_-SzYKxgek"\
          }\
      }\
  }';

var p521_key_spki = 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCCAc9n4N7ZOr_tTu\
_wAOmPKi4qTp5X3su6O3010hxmBYj9zI4u_0dm6UZa0LsjdfvcAET6vH3mEApvGKpDWrRsAA_nJhyQ20ca7Nn0Zvyiq54FfCAblGK7kuduF\
BTPkxv9eOjiaeGp7V_f3qV1kxS_Il2LY7Tc5l2GSlW_-SzYKxgek';

var b283_key = 
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.b283",\
            "X": "A0QgZzqf_IMeC-sOCBEOZhGmGHD0luoasQAK4-AVYtk0u2bD",\
            "Y": "BDdnv7LEFj3pN18G8NfTdf6nW171eWS6DLPjstH4i-wSgehw"\
          }\
      }\
  }';

var b283_key_spki = 'MF4wEAYHKoZIzj0CAQYFK4EEABEDSgAEA0QgZzqf_IMeC-sOCBEOZhGm\
GHD0luoasQAK4-AVYtk0u2bDBDdnv7LEFj3pN18G8NfTdf6nW171eWS6DLPjstH4i-wSgehw';

var p192_key = 
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.p192",\
            "X": "QWOcZWv7yoeLxbxtA6CHZoSdpmlg_u69",\
            "Y": "QtAQygGMLDy4Lp2MLtTYQlyQZGUfCQQv"\
          }\
      }\
  }';

var p192_key_spki = 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEQWOcZWv7yoeLxbxtA6CHZ\
oSdpmlg_u69QtAQygGMLDy4Lp2MLtTYQlyQZGUfCQQv';

var p384_key = 
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",\
            "X": "MyQMdQM9i47obgf_KDINLfjPaa03y8S_dDenvY5ULGOmoVlki6cvGRpL0QCiw_XD",\
            "Y": "JwLihlcNyevQvl30kqwVlyHWNSZ1z1LGO4VyxmrMdb8R2egVzMakm4PtPJjf5gMX"\
          }\
      }\
  }';

var p384_key_spki = 'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEMyQMdQM9i47obgf_KDINLf\
jPaa03y8S_dDenvY5ULGOmoVlki6cvGRpL0QCiw_XDJwLihlcNyevQvl30kqwVlyHWNSZ1z1LGO4VyxmrMdb8R2egVzMakm4PtPJjf5gMX';

var brainpool256_key =
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1",\
            "X": "AZ8WB15YNakVM9TeblaZh2HmmO2lDTarnXROAh7LO0Q",\
            "Y": "lal3Vzb5AjElCdazXnpCaa2gdU2LrMucG51oRHXOoHM"\
          }\
      }\
  }';

var brainpool256_key_spki = 'MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABAGfFgdeWDWpF\
TPU3m5WmYdh5pjtpQ02q510TgIeyztElal3Vzb5AjElCdazXnpCaa2gdU2LrMucG51oRHXOoHM';

var b163_key = 
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.b163",\
            "X": "B0M_ADx-Ma7KuLYX1kiHkeA5be9Z",\
            "Y": "YrAnUJj08HWJ3wnTfpWzy-S0t-c"\
          }\
      }\
  }';

var b163_key_spki = 'MEAwEAYHKoZIzj0CAQYFK4EEAA8DLAAEB0M_ADx-Ma7KuLYX1kiHkeA5\
be9ZAGKwJ1CY9PB1id8J036Vs8vktLfn';

var b233_key =
'{\
    "PublicKey": \
      {\
        "EC": \
          {\
            "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.b233",\
            "X": "_b9j6YxMzS-qk6p0dY_WCf5_04gyFaVwdHn6PGg",\
            "Y": "kotlfOdTNbKK5Z8co1-Ykh22rpMorG0llNrJe2Q"\
          }\
      }\
  }';

var b233_key_spki = 'MFIwEAYHKoZIzj0CAQYFK4EEABsDPgAEAP2_Y-mMTM0vqpOqdHWP1gn-f9OIMhW\
lcHR5-jxoAJKLZXznUzWyiuWfHKNfmJIdtq6TKKxtJZTayXtk';

var cert = "MIIDYzCCAkugAwIBAgIGAUOeUH5GMA0GCS\
qGSIb3DQEBCwUAMEMxEzARBgoJkiaJk_IsZAEZFgNvcmcxFjAUBgoJkiaJk_IsZAEZFgZ3ZWJwa2kxFDASBgNVBAMTC0RlbW8gU3ViIENBMB4XD\
TE0MDExNzAzNDgzMVoXDTM5MDExNzAzNDgzMVowQzEjMCEGCSqGSIb3DQEJARYUam9obi5kb2VAZXhhbXBsZS5jb20xHDAaBgNVBAMTE0tleUdl\
bjIgVHJ1c3RBbmNob3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp61eV2UkUj8Fx5XYVA60l7SCXpISCmWdSPB_4Bbcw7Naa_x2\
fkyNsD179_dZPy3FbaQtNzqLIo6EPXaLYLWOGKjnpzp2MZXYKxNfwSccPjxhSyO40zaDY5CLP4QfzUVVvD4SETzQGqxSJXMXzUPzePBiUGG5qO\
k8ZxGv12lmGThfiTQJC2ENzguwjEELejPQrOAQIbG-_CYqUsYBt0alJBAkD89WQ7M9ssJx7kPuqdD32YMBNOPc0jAswrpsFB-1narT33L2wkpN\
UK9DnKsrvIu1nCp0u6PaMDeeHL1TR51vzpZvDUMUvL2kE-e0iqN_Due0sYIpU9Qh0wy952shjAgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0PA\
QH_BAQDAgOIMB0GA1UdDgQWBBQeM7I_s8St2uxNVg4AUyrAOU4LhDAfBgNVHSMEGDAWgBRZXCF2vVvvaakHecbUVh7jS1yIVTANBgkqhkiG9w\
0BAQsFAAOCAQEAGhQMWLwV1sK1QQvXM_P0_VznWsXK8OGXZ7XSk2Ja9ajrECempZKBkDCQ63GiUSDaKjkXIkA9b9VKX6lMNytvOTHWIzh4cH49\
5cyhKtQ3UT1DNOakqrqkAlkWCjpOUerUNyYJRhgtd5xRssMUo4O1QB-PPniM01PStB6OrXWjc2OvSX6-EZwsZbPTOSSdUQK9jQ8V6MSC4rz5cQ\
2JHizYBx_6h-Kg8_xHKCLZc__mV9rHhByW0hP2HbBocjXg4uUCAOS8GVPnD_OoJ4rYtd_AyHRuedOnG-AwwLnKNGZSKsMDA89BE79FxkLf8cnS\
UnjPrTE9tPGAsi7a2CfSZz8VXg";

var cert_v1 = "MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZ\
XJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIg\
UG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0\
BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZX\
J0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgU\
G9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0B\
CQEWEWluZm9AdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5avIWZJV16vYdA757tn2VUdZZUc\
OBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zfN1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7_nHk01xC-YDgkRoKWzk2Z_M_VX\
wbP7RfZHM047QSv4dk-NoS_zcnwbNDu-97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADt_UG9vUJSZSWI4OB9L-KXIPqeCgf\
Yrx-jFzug6EILLGACOTb2oWH-heQC1u-mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV-mWwD5MlM_Mtsq2azSiGM5bUMMj4Qssxsod\
yamEwCW_POuZ6lcg5Ktz885hZo-L7tdEy8W9ViH0Pd";

deserializeTest (b163_key_spki, b163_key);

deserializeTest (b233_key_spki, b233_key);

deserializeTest (b283_key_spki, b283_key);

deserializeTest (p192_key_spki, p192_key);

deserializeTest (p256_key_spki, p256_key);
deserializeTest (p256_key_spki, p256_key_xml);

deserializeTest (p384_key_spki, p384_key);

deserializeTest (p521_key_spki, p521_key);

deserializeTest (brainpool256_key_spki, brainpool256_key);

deserializeTest (rsa_2048_key_spki, rsa_2048_key);

certReader (cert);

certReader (cert_v1);

//dnTest ("CN=John\\+Doe\u20ac");
dnTest ("John");
dnTest ("Jo,;:=hn\\");
dnTest ("Jo\u20achn");
dnTest ("Jo\u00c5hn");

console.debug ("Key serialization tests successful!");


