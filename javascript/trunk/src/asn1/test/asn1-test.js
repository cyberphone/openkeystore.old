function badASN1 (raw_asn1, error)
{
    var failed = false;
    try
    {
        new org.webpki.asn1.ParsedASN1Sequence (raw_asn1);
        failed = true;
    }
    catch (err)
    {
        failed = err.indexOf (error) < 0;
        error = "got: " + err + " expected: " + error;
    }
    if (failed) throw error;
}

function sequence (raw_asn1, components)
{
    var seq = org.webpki.asn1.ParsedASN1Sequence (new Uint8Array (raw_asn1));
    for (var i = 0; i < 5; i++)
    {
        var failed = false;
        try
        {
            seq.getComponent (i);
            failed = i >= components;
        }
        catch (err)
        {
            failed = err.indexOf ("Component index out of range") < 0 || i < components;
        }
        if (failed) throw "component: " + i;
    }
}

function badzero (raw_asn1, ok_with_zero)
{
    var failed = false;
    try
    {
        new org.webpki.asn1.ParsedASN1Object (raw_asn1);
        failed = !ok_with_zero;
    }
    catch (err)
    {
        failed = err.indexOf ("Zero-length body not permitted for tag") < 0 || ok_with_zero;
    }
    if (failed) throw "Zero problem: " + ok_with_zero;
}

if (!org.webpki.util.ByteArray.equals (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.SEQUENCE, []).encode (),
        new Uint8Array ([org.webpki.asn1.TAGS.SEQUENCE, 0]))) throw "SEQ error";
badASN1 (new Uint8Array ([org.webpki.asn1.TAGS.SEQUENCE, 1]), "Buffer underrun");
badASN1 (org.webpki.util.ByteArray.add (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.SEQUENCE, []).encode (),
                                                               new Uint8Array ([0])), "Sequence length");
badASN1 (new Uint8Array (org.webpki.asn1.LIBRARY_LIMIT + 1), "Exceeded library limit");

sequence ([org.webpki.asn1.TAGS.SEQUENCE, 0], 0);
sequence ([org.webpki.asn1.TAGS.SEQUENCE, 3, org.webpki.asn1.TAGS.INTEGER, 1, 8], 1);
sequence ([org.webpki.asn1.TAGS.SEQUENCE, 5, org.webpki.asn1.TAGS.INTEGER, 1, 8, org.webpki.asn1.TAGS.NULL, 0], 2);

badzero ([org.webpki.asn1.TAGS.NULL, 0], true);
badzero ([org.webpki.asn1.TAGS.SEQUENCE, 0], true);
badzero ([org.webpki.asn1.TAGS.INTEGER, 0], false);
badzero ([org.webpki.asn1.TAGS.BITSTRING, 0], false);
badzero ([org.webpki.asn1.TAGS.OID, 0], false);
badzero ([org.webpki.asn1.TAGS.OCTET_STRING, 0], false);

var indent = 0;
function spaceOut ()
{
    var buffer = "";
    for (var i = 0; i < indent; i++)
    {
        buffer += ' ';
    }
    return buffer;    
}
function printAsn1 (asn1_object)
{
    var buffer = spaceOut () + "TAG(" + asn1_object.tag.toString () + ")";
    if (asn1_object.tag == org.webpki.asn1.TAGS.SEQUENCE || asn1_object.tag == org.webpki.asn1.TAGS.SET)
      {
        console.debug (buffer);
        indent += 2;
        console.debug (spaceOut () + '{');
        indent += 2;
        for (var i = 0; i < asn1_object.numberOfComponents (); i++)
        {
            printAsn1 (asn1_object.getComponent (i));
        }
        indent -= 2;
        console.debug (spaceOut () + '}');
        indent -= 2;
      }
    else
    {
        console.debug (buffer + " " + org.webpki.util.ByteArray.toHex (asn1_object.body));
    }
}

printAsn1 (new org.webpki.asn1.ParsedASN1Object (new Uint8Array ([org.webpki.asn1.TAGS.SEQUENCE, 5, org.webpki.asn1.TAGS.INTEGER, 1, 8, org.webpki.asn1.TAGS.NULL, 0])));

var cert = org.webpki.util.Base64URL.decode ("MIIDYzCCAkugAwIBAgIGAUOeUH5GMA0GCS\
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
UnjPrTE9tPGAsi7a2CfSZz8VXg");

var cert_v1 = org.webpki.util.Base64URL.decode ("MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZ\
XJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIg\
UG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0\
BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZX\
J0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgU\
G9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0B\
CQEWEWluZm9AdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5avIWZJV16vYdA757tn2VUdZZUc\
OBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zfN1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7_nHk01xC-YDgkRoKWzk2Z_M_VX\
wbP7RfZHM047QSv4dk-NoS_zcnwbNDu-97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADt_UG9vUJSZSWI4OB9L-KXIPqeCgf\
Yrx-jFzug6EILLGACOTb2oWH-heQC1u-mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV-mWwD5MlM_Mtsq2azSiGM5bUMMj4Qssxsod\
yamEwCW_POuZ6lcg5Ktz885hZo-L7tdEy8W9ViH0Pd");

console.debug (org.webpki.util.ByteArray.toHex (cert));

printAsn1 (new org.webpki.asn1.ParsedASN1Object (cert));
        
printAsn1 (new org.webpki.asn1.ParsedASN1Object (cert_v1));

console.debug ("ASN.1 tests successful!");
