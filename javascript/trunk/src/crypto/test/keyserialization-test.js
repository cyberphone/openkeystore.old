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
        failed = false;
    }
    if (failed) throw "Should have failed";
}

function certReader (cert_in_b64)
{
    var cert_data = new org.webpki.crypto.DecodedX509Certificate (org.webpki.util.Base64URL.decode (cert_in_b64));
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

function rawDnTest (binary)
{
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
                .addComponent (binary)
              )
          )
    .encode ();
var java_dn =  "" +  AntCrypto.getDistinguishedName (org.webpki.util.Base64URL.encode (asn1));

var json_dn = org.webpki.crypto.getDistinguishedName (new org.webpki.asn1.ParsedASN1Sequence (asn1));
if (java_dn.equals (json_dn))
{
    console.debug ("DN=" + java_dn);
}
else
{
    throw "DN fail " + json_dn + " " + java_dn;
}
}

function asn1DnTest (utf8)
{
    rawDnTest (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.UTF8STRING, utf8).encode ());
}

function dnTest (unicode_argument)
{
    asn1DnTest (org.webpki.util.Base64URL.decode ("" + AntCrypto.convertToUTF8 (unicode_argument)));
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

var other_cert = "MIIHwzCCBaugAwIBAgIUfQuXudo6SVbkrJosltTgAtIQ2PowDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBh\
MCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxJTAjBgNVBAsTHFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxKDAmBg\
NVBAMTH1F1b1ZhZGlzIE5vIFJlbGlhbmNlIFJvb3QgQ0EgRzIwHhcNMTIwNDEyMTI0NDI0WhcNMTUwNDEyMTI0NDI0WjBYMQswCQ\
YDVQQGEwJMSTEpMCcGA1UEChMgTGllY2h0ZW5zdGVpbmlzY2hlIExhbmRlc2JhbmsgQUcxHjAcBgNVBAMTFUxMQiBSb290IENBIH\
B1YmxpYyB2MjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL4Q3hTuqb49g3eNz6l8zW_IjdluqydipXKR7fhfh3j9CO\
OoyQ5MtdpHNGKl4bkojaJ6wrGM2wgyATAKZePToxH5weMlktpwvyc7Y1M5tIe5LPj3rzOB_X3V-0x4wlhuDgPRvG9Trd9TftW0RjX\
aAY8x_yi_tJyG6-cIK-uYT09Md7WxXIPOTN-axj7wsVLzMiwcG11WeyIsgqVPQwoQATS1r_m4oCnXVx7NTsbjn-au573HiXzU97aF\
xrPxg7o2acHYVLUuFcgpupibYGJIvAqJbCGkQB3MAyGkHnnVckyidFWjR1FKY9diLtC3gGTlu3lTnw3GjmVLLSDpNQBXEuAy8xsQe\
g7CvjLEe3Zv7nqmiHtRDUqbwSolPanY4WsdZDyIKDEf8pNC8sFph-e3JVu7yKQhl-OPVgRrXAWED5iNqha7bGrY9zEObkSSGTTaXt\
opRMObEWSVwYTt9wfpEBEWZAlPZnGVRRvqS_lZaRtvSqmtihnSAA51Yv9T7kPE82hhOQ3HvMgG4QMh9DpdkYl9ZEHOm87xcD_Wpa-\
qbeAVa6_zyRWst89pFyO2qM6I5a5lulYvdHrJDMT2_0oAPs1tgfpNlOlruA2A-uKXmaROzj0xg-Uvf5R8GBocj7q10wiD_AYdmdX8\
s2O2Ybbiqu_WGDgxJbQIZp9Q7WSis9CFAgMBAAGjggJiMIICXjASBgNVHRMBAf8ECDAGAQH_AgEBMHQGCCsGAQUFBwEBBGgwZjAqB\
ggrBgEFBQcwAYYeaHR0cDovL29jc3AucXVvdmFkaXNnbG9iYWwuY29tMDgGCCsGAQUFBzAChixodHRwOi8vdHJ1c3QucXVvdmFkaX\
NnbG9iYWwuY29tL3F2bnJjYWcyLmNydDBRBgNVHR4BAf8ERzBFoEMwD4ENQGp1cmF0cnVzdC5saTAJgQdAbGxiLmxpMAmBB0BsbGI\
uY2gwCYEHQGxsYi5hdDAPgQ1AYmFua2xpbnRoLmNoMIHIBgNVHSAEgcAwgb0wgboGDCsGAQQBvlgAA4hMADCBqTCBggYIKwYBBQUH\
AgIwdhp0QW55IHVzZSBvZiB0aGlzIENlcnRpZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIExMQiBDZXJ0aWZpY\
2F0ZSBQb2xpY3kgLyBDZXJ0aWZpY2F0aW9uIFByYWN0aWNlIFN0YXRlbWVudC4wIgYIKwYBBQUHAgEWFmh0dHBzOi8vd3d3LmxsYi\
5saS9wa2kwDgYDVR0PAQH_BAQDAgEGMCcGA1UdJQQgMB4GCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwkwHwYDVR0jBBgwFoA\
Ur9DvHfgJ-TQRH9RXVvngO6ZhxDcwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybC5xdW92YWRpc2dsb2JhbC5jb20vcXZucmNh\
ZzIuY3JsMB0GA1UdDgQWBBQO3mVRfY1r_g3d36XUC89aDocfRzANBgkqhkiG9w0BAQUFAAOCAgEACHiNrQpM2Q4oMsfthke5iwlDj\
JMRNGK6u7NhFbFd6aC7cGfgnJfv6RMlmiVpmA9QXieeRtG2zMiDMAWq_7_mo3z006InAQ08cgyX7XYfBWMLDl1kR1LSYWvxDiLa1E\
U-I_Nv9lpEhCpKQgj69WPLVmjZoNRNV-PHOyspmf3yt4PHJt4tBvbwxBpz_B2d--EuwklIbqhq1s1px_D-bHIIEBbp1xDkDIJAUVN\
A0cfDdpYW2niz9QiGHessDsLgK1hW2xW3W2qzHVGSmuO1D8EmGhhK0iJjl088DLocmZr0iZWj6utyGEmZWeDfvLLiUFun1MOAYF9B\
hMQ0dJXKD1A9ubK6CKNEYYAAcqZTbybyFgMGutIQ3flWEW0FTj0MY8U81lK8av05j7u-J9CiFxx7aSXJilB7HqbkQjKMOeL9hdG2U\
AbtOfaWZpDPpizD58i-3J5B6mKACDCgkB0b1DmXhqf7A7fmoo-vwCyRx4AyWXxxJXZd7tuQUWOuUgnKZTbNViW5Cr8UMvmq934FYd\
Ka0MFb-IME_H9vgpejp2cD_3cc20QkfYeLqm5V7nKZeIm4jB7X2mbE-z0wFlbHiBJ7cgqi-XkW4lXqRsUISNtT5PyPfCjI5BlI5jb\
tb7u6f3Vq4nzkZQFETkW8URQYYGZ6A-0BVjMn2gNDmBmc32EAzXI";

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

certReader (other_cert);

//dnTest ("CN=John\\+Doe\u20ac");
dnTest ("John");
dnTest ("Jo,;:=hn\\");
dnTest ("Jo\u20achn");
dnTest ("Jo\u00c5hn");

asn1DnTest (new Uint8Array ([0xEC, 0xA1, 0xB0, 0xEC, 0x83, 0x81, 0xEB, 0x9E, 0x98]));

rawDnTest (new Uint8Array ([0x1E, 0x08, 0x00, 0x41, 0x20, 0xAC, 0x00, 0xC5, 0x00, 0x42]));

console.debug ("Key serialization tests successful!");


