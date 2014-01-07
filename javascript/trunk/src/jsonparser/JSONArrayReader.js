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
/*                        JSONArrayReader                         */
/*================================================================*/

webpki.org.json.JSONArrayReader = function (/* Vector<webpki.org.json.JSONValue> */array)
{
    this.index = 0;
    this.array = array;
};

/* public boolean */webpki.org.json.JSONArrayReader.prototype.hasMore = function ()
{
    return this.index < this.array.length;
};

/* void */webpki.org.json.JSONArrayReader.prototype._inRangeCheck = function ()
{
    if (!this.hasMore ())
    {
        webpki.org.json.JSONError._error ("Trying to read past of array limit: " + this.index);
    }
};

/* Object */webpki.org.json.JSONArrayReader.prototype._get = function (/* webpki.org.json.JSONTypes */expected_type)
{
    this._inRangeCheck ();
    /* webpki.org.json.JSONValue */var value = this.array[this.index++];
    if (!expected_type.isCompatible (value.type))
    {
        webpki.org.json.JSONError._error ("Incompatible request: " +
                "Read=" + webpki.org.json.JSONValue.prototype.getJSONTypeName (value.type) +
                ", Expected=" + webpki.org.json.JSONValue.prototype.getJSONTypeName (expected_type));
    }
    return value.value;
};

/* public String */webpki.org.json.JSONArrayReader.prototype.getString = function ()
{
    return /* (String) */this._get (webpki.org.json.JSONTypes.STRING);
};

/* public int */webpki.org.json.JSONArrayReader.prototype.getInt = function ()
{
    return parseInt (/* (String) */this._get (webpki.org.json.JSONTypes.INTEGER));
};

/* public long */webpki.org.json.JSONArrayReader.prototype.getLong = function ()
{
    return this._get (webpki.org.json.JSONTypes.INTEGER);
};

/* public BigInteger */webpki.org.json.JSONArrayReader.prototype.getBigInteger = function ()
{
    return this._get (webpki.org.json.JSONTypes.INTEGER);
};

/* public BigDecimal */webpki.org.json.JSONArrayReader.prototype.getBigDecimal = function ()
{
    return new this, _get (webpki.org.json.JSONTypes.DECIMAL);
};
/*
 public GregorianCalendar getDateTime () throws IOException
 {
 return ISODateTime.parseDateTime (getString ());
 }

 public double getDouble () throws IOException
 {
 return new Double ((String) get (webpki.org.json.JSONTypes.DOUBLE));
 }

 public boolean getBoolean () throws IOException
 {
 return new Boolean ((String) get (webpki.org.json.JSONTypes.BOOLEAN));
 }

 public boolean getIfNULL () throws IOException
 {
 if (getElementType () == webpki.org.json.JSONTypes.NULL)
 {
 scanAway ();
 return true;
 }
 return false;
 }
 */
/* public webpki.org.json.JSONArrayReader */webpki.org.json.JSONArrayReader.prototype.getArray = function ()
{
    return new webpki.org.json.JSONArrayReader (/* (Vector<webpki.org.json.JSONValue>) */this._get (webpki.org.json.JSONTypes.ARRAY));
};
/*
 public webpki.org.json.JSONTypes getElementType () throws IOException
 {
 _inRangeCheck ();
 return array.elementAt (index).type;
 }
 */
/* public webpki.org.json.JSONObjectReader */webpki.org.json.JSONArrayReader.prototype.getObject = function ()
{
    return new webpki.org.json.JSONObjectReader (/* (webpki.org.json.JSONObject) */this._get (webpki.org.json.JSONTypes.OBJECT));
};
/*
 public void scanAway () throws IOException
 {
 get (getElementType ());
 }
 }
 */
