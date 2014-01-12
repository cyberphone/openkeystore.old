console.debug ("Hi BigInteger");

var bigint = org.webpki.math.BigInteger.fromString ("678");
bigint = org.webpki.math.BigInteger.fromString (679);
console.debug (bigint.toString ());
console.debug (org.webpki.math.BigInteger.fromString (679).toString (16));
console.debug (org.webpki.math.BigInteger.fromString ("abcdef013456789", 16).toString (16));

if (org.webpki.math.BigInteger.fromString ("0").toString () != "0")
{
    throw "ZERO!";
}
if (org.webpki.math.BigInteger.fromString ("01").toString () != "1")
{
    throw "LEADING ZERO!";
}
if (org.webpki.math.BigInteger.fromString ("000000").getByteArray ().length != 1)
{
    throw "LEADING ZERO BIN!";
}
if (!org.webpki.math.BigInteger.fromString ("000000").isZero () || !org.webpki.math.BigInteger.fromString ("0").isZero ())
{
    throw "ZERO TEST!";
}
function runit (base)
{
    for (var times = 0; times < 100; times++)
    {
        for (var i = 1; i < 100; i++)
        {
            var iarr = new Uint8Array(i);
            for (var j = 0; j < i; j++)
            {
                iarr[j] =  Math.floor(Math.random()*256);
            }
            var bigint = new org.webpki.math.BigInteger (iarr);
            var string = bigint.toString (base);
//            console.debug ("Value=" + string);
            var bigint2 = org.webpki.math.BigInteger.fromString (string, base);
            var arr = bigint2.getByteArray ();
            var offset = 0;
            while (iarr[offset] == 0 && offset < iarr.length - arr.length)
            {
                offset++;
            }
            if (iarr.length - offset != bigint.getByteArray ().length) throw "Zero error";
            if (!bigint.equals (bigint2))
            {
                throw "Equals failed";
            }
        }
    }
}
runit (16);
runit (10);
console.debug ("We did it!");

