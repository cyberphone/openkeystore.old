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

function JSONArrayReader (/* Vector<JSONValue> */array)
{
    this.index = 0;
    this.array = array;
}

/* public boolean */JSONArrayReader.prototype.hasMore = function ()
{
    return this.index < this.array.length;
};

/* void */JSONArrayReader.prototype._inRangeCheck = function ()
{
    if (!this.hasMore ())
    {
        JSONObject._error ("Trying to read past of array limit: " + this.index);
    }
};

/* Object */JSONArrayReader.prototype._get = function (/* JSONTypes */expected_type)
{
    this._inRangeCheck ();
    /* JSONValue */var value = this.array[this.index++];
    if (!expected_type.isCompatible (value.type))
    {
        JSONObject._error ("Incompatible request: " +
                "Read=" + JSONValue.prototype.getJSONTypeName (value.type) +
                ", Expected=" + JSONValue.prototype.getJSONTypeName (expected_type));
    }
    return value.value;
};

/* public String */JSONArrayReader.prototype.getString = function ()
{
    return /* (String) */this._get (JSONTypes.STRING);
};

/* public int */JSONArrayReader.prototype.getInt = function ()
{
    return parseInt (/* (String) */this._get (JSONTypes.INTEGER));
};

/* public long */JSONArrayReader.prototype.getLong = function ()
{
    return this._get (JSONTypes.INTEGER);
};

/* public BigInteger */JSONArrayReader.prototype.getBigInteger = function ()
{
    return this._get (JSONTypes.INTEGER);
};

/* public BigDecimal */JSONArrayReader.prototype.getBigDecimal = function ()
{
    return new this, _get (JSONTypes.DECIMAL);
};
/*
 public GregorianCalendar getDateTime () throws IOException
 {
 return ISODateTime.parseDateTime (getString ());
 }

 public double getDouble () throws IOException
 {
 return new Double ((String) get (JSONTypes.DOUBLE));
 }

 public boolean getBoolean () throws IOException
 {
 return new Boolean ((String) get (JSONTypes.BOOLEAN));
 }

 public boolean getIfNULL () throws IOException
 {
 if (getElementType () == JSONTypes.NULL)
 {
 scanAway ();
 return true;
 }
 return false;
 }
 */
/* public JSONArrayReader */JSONArrayReader.prototype.getArray = function ()
{
    return new JSONArrayReader (/* (Vector<JSONValue>) */this._get (JSONTypes.ARRAY));
};
/*
 public JSONTypes getElementType () throws IOException
 {
 _inRangeCheck ();
 return array.elementAt (index).type;
 }
 */
/* public JSONObjectReader */JSONArrayReader.prototype.getObject = function ()
{
    return new JSONObjectReader (/* (JSONObject) */this._get (JSONTypes.OBJECT));
};
/*
 public void scanAway () throws IOException
 {
 get (getElementType ());
 }
 }
 */
