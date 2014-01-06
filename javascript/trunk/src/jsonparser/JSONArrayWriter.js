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

function JSONArrayWriter (optional_array)
{
   /* Vector<JSONValue> */this.array = optional_array === undefined ? [] : optional_array;
}

/* JSONArrayWriter */JSONArrayWriter.prototype._add = function (/* JSONTypes */type, /* Object */value)
{
    this.array[this.array.length] = new JSONValue (type, value);
    return this;
};

/* public JSONArrayWriter */JSONArrayWriter.prototype.setString = function (/* String */value)
{
    return this._add (JSONTypes.STRING, value);
};

/* public JSONArrayWriter */JSONArrayWriter.prototype.setInt = function (/* int */value)
{
    return this._add (JSONTypes.INTEGER, value);
};

/*
    public JSONArrayWriter setLong (long value) throws IOException
      {
        return add (JSONTypes.INTEGER, Long.toString (value));
      }

    public JSONArrayWriter setBigDecimal (BigDecimal value) throws IOException
      {
        return add (JSONTypes.INTEGER, value.toString ());
      }

    public JSONArrayWriter setBigInteger (BigInteger value) throws IOException
      {
        return add (JSONTypes.INTEGER, value.toString ());
      }

    public JSONArrayWriter setDouble (double value) throws IOException
      {
        return add (JSONTypes.DOUBLE, Double.toString (value));
      }

    public JSONArrayWriter setBoolean (boolean value) throws IOException
      {
        return add (JSONTypes.BOOLEAN, Boolean.toString (value));
      }

    public JSONArrayWriter setNULL () throws IOException
      {
        return add (JSONTypes.NULL, "null");
      }

    public JSONArrayWriter setDateTime (Date date_time) throws IOException
      {
        return setString (ISODateTime.formatDateTime (date_time));
      }

/* public JSONArrayWriter */JSONArrayWriter.prototype.setArray = function ()
{
    /* Vector<JSONValue> */var new_array = [] /* new Vector<JSONValue> () */;
    this._add (JSONTypes.ARRAY, new_array);
    return new JSONArrayWriter (new_array);
};

/* public JSONObjectWriter */JSONArrayWriter.prototype.setObject = function ()
{
    /* JSONObject */var holder = new JSONObject ();
    this._add (JSONTypes.OBJECT, holder);
    return new JSONObjectWriter (holder);
};

/* public String */JSONArrayWriter.prototype.serializeJSONArray = function (/* JSONOutputFormats */output_format)
{
    /* JSONObject */var dummy = new JSONObject ();
    dummy._setArray (new JSONValue (JSONTypes.ARRAY, this.array));
    return new JSONObjectWriter (dummy).serializeJSONObject (output_format);
};
