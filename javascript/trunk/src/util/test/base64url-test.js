for (var times = 0; times < 1000; times++)
{
    for (var i = 0; i < 10; i++)
    {
        var iarr = new Uint8Array(i);
        for (var j = 0; j < i; j++)
        {
            iarr[j] =  Math.floor(Math.random()*256);
        }
        var b64 = org.webpki.util.Base64URL.encode (iarr);
        console.debug ("Base64URL=" + b64);
        var arr = org.webpki.util.Base64URL.decode (b64);
        if (arr.length != iarr.length) throw "Length error";
        for (var q = 0; q < arr.length; q++)
        {
            if (arr[q] != iarr[q]) throw "Content error: " + b64;
        }
    }
}
var should_fail = true;
try
{
    var h = org.webpki.util.Base64URL.decode ("a");
    should_fail = false;
}
catch (err)
{
}
if (!should_fail)
{
    throw "Bad";
}
should_fail = true;
try
{
    var h = org.webpki.util.Base64URL.decode ("+xdFdYg");
    should_fail = false;
}
catch (err)
{
}
if (!should_fail)
{
    throw "Bad";
}
should_fail = true;
try
{
    var h = org.webpki.util.Base64URL.decode ("/xdFdYg");
    should_fail = false;
}
catch (err)
{
}
if (!should_fail)
{
    throw "Bad";
}
// We are pretty strict, yes...
for (var i = 0; i < 64; i++)
{
    try
    {
        var string = "A" + org.webpki.util.Base64URL.BASE64URL[i]; 
        should_fail = i % 16 > 0;
        org.webpki.util.Base64URL.decode (string);
    }
    catch (err)
    {
        should_fail = !should_fail;
    }
    if (should_fail)
    {
        throw "Bad" + i;
    }
    try
    {
        var string = "AA" + org.webpki.util.Base64URL.BASE64URL[i]; 
        should_fail = i % 4 > 0;
        org.webpki.util.Base64URL.decode (string);
    }
    catch (err)
    {
        should_fail = !should_fail;
    }
    if (should_fail)
    {
        throw "Bad" +i;
    }
}
console.debug ("Done, it worked!");
