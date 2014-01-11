/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*================================================================*/
/*                           BigInteger                           */
/*================================================================*/

// The JS version of BigInteger is just a thin wrapper over an "Uint8Array" and
// the only functionality offered is a test for equivalence.  It is anticipated
// that all cryptographic functions are performed in other and lower layers of
// the platform.

/* BigInteger */org.webpki.math.BigInteger = function (optional_value)
{
    this.value = optional_value === undefined ? null : optional_value;
};

org.webpki.math.BigInteger._error = function (message)
{
    throw "MATHException: " + message;
};

org.webpki.math.BigInteger._base = function (/* int */optional_10_or_16_base)
{
    if (optional_10_or_16_base === undefined)
    {
        return 10;
    }
    else if (optional_10_or_16_base == 10)
    {
        return 10;
    }
    else if (optional_10_or_16_base == 16)
    {
        return 16;
    }
    else
    {
        org.webpki.math.BigInteger._error ("Incorrect base argument, only 10 and 16 are supported");
    }
    throw "MATHException: " + message;
};

/* bool*/ org.webpki.math.BigInteger._isZero = function (bigint)
{
    for (var i = 0; i < bigint.length; i++)
    {
        if (bigint[i] != 0)
        {
            return false;
        }
    }
    return true;
};

/* void */org.webpki.math.BigInteger._setSmallValue = function (/* Unit8Array*/bigint, /* int*/value)
{
    var i = bigint.length;
    bigint[--i] = value;
    while (--i >= 0)
    {
        bigint[i] = 0;
    }
};

/* int */org.webpki.math.BigInteger._getNextDigit = function (/* Unit8Array*/dividend, /* int*/divisor)
{
    var remainder = 0;
    for (var i = 0; i < dividend.length; i++)
    {
        remainder = dividend[i] | (remainder << 8);
        dividend[i] = Math.floor (remainder / divisor);
        remainder = Math.floor (remainder % divisor);
    }
    return remainder;
};

/* BigInteger */org.webpki.math.BigInteger.fromString = function (/* String */string, /* int */optional_10_or_16_base)
{
    var base = org.webpki.math.BigInteger._base (/* int */optional_10_or_16_base);
    if (typeof string  == 'number')
    {
        string = string.toString ();
    }
    else if (typeof string  != 'string')
    {
        org.webpki.math.BigInteger._error ("Expected a string argument");
    }
    if (string.length == 0)
    {
        org.webpki.math.BigInteger._error ("Empty string not allowed");
    }
    var bi = new org.webpki.math.BigInteger ();
    var result = [];
    result[0] = 0;
    for (var i = 0; i <  string.length; i++)
    {
        var n;
        /* char */var c = string.charAt (i);
        if (c >= '0' && c <= '9')
        {
            n = c.charCodeAt (0) - 48;
        }
        else if (base == 10)
        {
            org.webpki.math.BigInteger._error ("Decimal number expected");

        }
        else if (c >= 'a' && c <= 'f')
        {
            n = c.charCodeAt (0) - 87;
        }
        else if (c >= 'A' && c <= 'F')
        {
            n = c.charCodeAt (0) - 55;
        }
        else
        {
            org.webpki.math.BigInteger._error ("Hexadecimal number expected");
        }
        var carry = 0;
        var j = 0;
        while (j < result.length)
        {
            var bigres = base * result[j] + n + carry;
            n = 0;
            bigres -= (carry = Math.floor (bigres / 256)) * 256;
            result[j++] = bigres;
            if (carry > 0 && j == result.length)
            {
                result[j] = 0;
            }
        }
    }
    bi.value = new Uint8Array (result.length);
    for (var i = 0; i < result.length; i++)
    {
        bi.value [result.length - i - 1] = result[i];
    }
    return bi;
};

/* Uint8Array */org.webpki.math.BigInteger.prototype.getByteArray = function ()
{
    if (!this.value)
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    return this.value;
};

/* boolean */org.webpki.math.BigInteger.prototype.equals = function (big_integer)
{
    if (!this.value || !big_integer.value) 
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    if (this.value.length != big_integer.value.length)
    {
        return false;
    }
    for (var i = 0; i < this.value.length; i++)
    {
        if (this.value[i] != big_integer.value[i])
        {
            return false;
        }
    }
    return true;
};

/* Uint8Array */org.webpki.math.BigInteger.prototype._getDivisor = function (index)
{
    var divisor = new Uint8Array (this.value.length + 1);
    var last = divisor.length - 1;
    for (var i = 0; i < divisor.length; i++)
    {
        divisor[i] = 0;
    }
    divisor[last] = 1;
    for (var i = 0; i < index; i++)
    {
        var carry = 0;
        var j = divisor.length;
        while (--j >= 0)
        {
            var bigres = this.base * divisor[j] + carry;
            bigres -= (carry = Math.floor (bigres / 256)) * 256;
            divisor[j] = bigres;
        }
    }
    return divisor;
};

/* String */org.webpki.math.BigInteger.prototype.toString = function (/* int */optional_10_or_16_base)
{
    if (!this.value)
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    var base = org.webpki.math.BigInteger._base (/* int */optional_10_or_16_base);
    if (org.webpki.math.BigInteger._isZero (this.value))
    {
        return "0";
    }
    var temp_string = "";
    var result = new Uint8Array (this.value);
    while (!org.webpki.math.BigInteger._isZero (result))
    {
        var digit = org.webpki.math.BigInteger._getNextDigit (result, base);
        temp_string += String.fromCharCode (digit + (digit > 9 ? 55 : 48));
    }
    var the_string = "";
    var i = temp_string.length;
    while (--i >= 0)
    {
        the_string += temp_string.charAt (i);
    }
    return the_string;
};
