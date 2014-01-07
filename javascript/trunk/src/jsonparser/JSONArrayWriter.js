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

 webpki.org.json.JSONArrayWriter = function (optional_array)
{
   /* Vector<webpki.org.json.JSONValue> */this.array = optional_array === undefined ? [] : optional_array;
};

/* webpki.org.json.JSONArrayWriter */webpki.org.json.JSONArrayWriter.prototype._add = function (/* webpki.org.json.JSONTypes */type, /* Object */value)
{
    this.array[this.array.length] = new webpki.org.json.JSONValue (type, value);
    return this;
};

/* public webpki.org.json.JSONArrayWriter */webpki.org.json.JSONArrayWriter.prototype.setString = function (/* String */value)
{
    return this._add (webpki.org.json.JSONTypes.STRING, value);
};

/* public webpki.org.json.JSONArrayWriter */webpki.org.json.JSONArrayWriter.prototype.setInt = function (/* int */value)
{
    return this._add (webpki.org.json.JSONTypes.INTEGER, value);
};

/*
    public webpki.org.json.JSONArrayWriter setLong (long value) throws IOException
      {
        return add (webpki.org.json.JSONTypes.INTEGER, Long.toString (value));
      }

    public webpki.org.json.JSONArrayWriter setBigDecimal (BigDecimal value) throws IOException
      {
        return add (webpki.org.json.JSONTypes.INTEGER, value.toString ());
      }

    public webpki.org.json.JSONArrayWriter setBigInteger (BigInteger value) throws IOException
      {
        return add (webpki.org.json.JSONTypes.INTEGER, value.toString ());
      }

    public webpki.org.json.JSONArrayWriter setDouble (double value) throws IOException
      {
        return add (webpki.org.json.JSONTypes.DOUBLE, Double.toString (value));
      }

    public webpki.org.json.JSONArrayWriter setBoolean (boolean value) throws IOException
      {
        return add (webpki.org.json.JSONTypes.BOOLEAN, Boolean.toString (value));
      }

    public webpki.org.json.JSONArrayWriter setNULL () throws IOException
      {
        return add (webpki.org.json.JSONTypes.NULL, "null");
      }

    public webpki.org.json.JSONArrayWriter setDateTime (Date date_time) throws IOException
      {
        return setString (ISODateTime.formatDateTime (date_time));
      }

/* public webpki.org.json.JSONArrayWriter */webpki.org.json.JSONArrayWriter.prototype.setArray = function ()
{
    /* Vector<webpki.org.json.JSONValue> */var new_array = [] /* new Vector<webpki.org.json.JSONValue> () */;
    this._add (webpki.org.json.JSONTypes.ARRAY, new_array);
    return new webpki.org.json.JSONArrayWriter (new_array);
};

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONArrayWriter.prototype.setObject = function ()
{
    /* webpki.org.json.JSONObject */var holder = new webpki.org.json.JSONObject ();
    this._add (webpki.org.json.JSONTypes.OBJECT, holder);
    return new webpki.org.json.JSONObjectWriter (holder);
};

/* public String */webpki.org.json.JSONArrayWriter.prototype.serializeJSONArray = function (/* webpki.org.json.JSONOutputFormats */output_format)
{
    /* webpki.org.json.JSONObject */var dummy = new webpki.org.json.JSONObject ();
    dummy._setArray (new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.ARRAY, this.array));
    return new webpki.org.json.JSONObjectWriter (dummy).serializeJSONObject (output_format);
};
