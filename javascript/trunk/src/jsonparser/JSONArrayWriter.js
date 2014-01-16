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
/*                         JSONArrayWriter                        */
/*================================================================*/

org.webpki.json.JSONArrayWriter = function (optional_array)
{
    /* JSONValue[] */this.array = optional_array === undefined ? [] : optional_array;
};

/* JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype._add = function (/* JSONTypes */type, /* Object */value)
{
    this.array[this.array.length] = new org.webpki.json.JSONValue (type, value);
    return this;
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setString = function (/* String */value)
{
    return this._add (org.webpki.json.JSONTypes.STRING, value);
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setInt = function (/* int */value)
{
    return this._add (org.webpki.json.JSONTypes.INTEGER, org.webpki.json.JSONObjectWriter._intTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setLong = function (/* BigInteger */value)
{
    return this.setBigInteger (value.getLong ());
};

// No real support for BigDecimal but at least text parsing is performed

/* public JSONArrayWriter */ org.webpki.json.JSONArrayWriter.prototype.setBigDecimal = function (/* BigDecimal */value)
{
    return this._add (org.webpki.json.JSONTypes.DECIMAL, org.webpki.json.JSONObjectWriter._bigDecimalTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setBigInteger = function (/* BigInteger */value)
{
    return this._add (org.webpki.json.JSONTypes.INTEGER, value.toString ());
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setDouble = function (/* double */value)
{
    return this._add (org.webpki.json.JSONTypes.DOUBLE, org.webpki.json.JSONObjectWriter._doubleTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setBoolean = function (/* boolean */value)
{
    return this._add (org.webpki.json.JSONTypes.BOOLEAN, org.webpki.json.JSONObjectWriter._boolTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setNULL = function ()
{
    return this._add (org.webpki.json.JSONTypes.NULL, "null");
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setDateTime = function (/* Date */date_time)
{
    return this.setString (date_time.toISOString ());
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setArray = function ()
{
    /* JSONValue[] */var new_array = [] /* new JSONValue[] () */;
    this._add (org.webpki.json.JSONTypes.ARRAY, new_array);
    return new org.webpki.json.JSONArrayWriter (new_array);
};

/* public JSONObjectWriter */org.webpki.json.JSONArrayWriter.prototype.setObject = function ()
{
    /* JSONObject */var holder = new org.webpki.json.JSONObject ();
    this._add (org.webpki.json.JSONTypes.OBJECT, holder);
    return new org.webpki.json.JSONObjectWriter (holder);
};

/* public String */org.webpki.json.JSONArrayWriter.prototype.serializeJSONArray = function (/* JSONOutputFormats */output_format)
{
    /* JSONObject */var dummy = new org.webpki.json.JSONObject ();
    dummy._setArray (new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, this.array));
    return new org.webpki.json.JSONObjectWriter (dummy).serializeJSONObject (output_format);
};
