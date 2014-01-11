console.debug ("Hi BigInteger");

var bigint = org.webpki.math.BigInteger.fromString ("678");
bigint = org.webpki.math.BigInteger.fromString (679);
console.debug (bigint.toString ());
console.debug (org.webpki.math.BigInteger.fromString (679).toString (16));
console.debug (org.webpki.math.BigInteger.fromString ("abcdef013456789", 16).toString (16));


var bi = org.webpki.math.BigInteger.fromString ("7");
//console.debug (bi.getByteArray ());
//org.webpki.math.BigInteger._error ("Bla");

var a = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
//console.debug (a.BYTES_PER_ELEMENT);

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
            console.debug ("Value=" + string);
            var bigint2 = org.webpki.math.BigInteger.fromString (string, base);
            var arr = bigint2.getByteArray ();
            var offset = 0;
            while (iarr[offset] == 0 && offset < iarr.length - arr.length)
            {
                offset++;
            }
            if (offset == 0 && !bigint.equals (bigint2))
            {
                throw "Equals failed";
            }
            if (arr.length != (iarr.length - offset)) throw "Length error" + arr.length;
            for (var q = 0; q < arr.length; q++)
            {
                if (arr[q] != iarr[q + offset]) throw "Content error";
            }
        }
    }
}
runit (16);
runit (10);

