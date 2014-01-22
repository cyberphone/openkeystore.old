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

console.debug ("ASN.1 tests successful!");
