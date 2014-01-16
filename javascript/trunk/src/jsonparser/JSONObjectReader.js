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
/*                        JSONObjectReader                        */
/*================================================================*/

 org.webpki.json.JSONObjectReader = function (/* org.webpki.json.JSONObject */json)
{
    this.json = json;
};

/* org.webpki.json.JSONValue */org.webpki.json.JSONObjectReader.prototype._getProperty = function (/* String */name, /* org.webpki.json.JSONTypes */expected_type)
{
    /* org.webpki.json.JSONValue */var value = this.json._getProperty (name);
    if (value == null)
    {
        org.webpki.json.JSONError._error ("Property \"" + name + "\" is missing");
    }
    if (!expected_type.isCompatible (value.type))
    {
        org.webpki.json.JSONError._error ("Type mismatch for \"" + name +
                           "\": Read=" + org.webpki.json.JSONValue.prototype.getJSONTypeName (value.type) +
                           ", Expected=" + org.webpki.json.JSONValue.prototype.getJSONTypeName (expected_type));
    }
    this.json.read_flag[name] = true;
    return value;
};

/* String */org.webpki.json.JSONObjectReader.prototype._getString = function (/* String */name, /* org.webpki.json.JSONTypes */expected)
{
    /* org.webpki.json.JSONValue */var value = this._getProperty (name, expected);
    return /* (String) */value.value;
};

/* public String */org.webpki.json.JSONObjectReader.prototype.getString = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.STRING);
};

/* public int */org.webpki.json.JSONObjectReader.prototype.getInt = function (/* String */name)
{
    return parseInt (this._getString (name, org.webpki.json.JSONTypes.INTEGER));
};

/* public BigInteger */org.webpki.json.JSONObjectReader.prototype.getLong = function (/* String */name)
{
    return this.getBigInteger (name).getLong ();
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.getBoolean = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.BOOLEAN) == "true";
};

/* public GregorianCalendar */org.webpki.json.JSONObjectReader.prototype.getDateTime = function (/* String */name)
{
    return new Date (this.getString (name));
};

/* Uint8Array */org.webpki.json.JSONObjectReader.prototype.getBinary = function (/* String */name)
{
    return org.webpki.util.Base64URL.decode (this.getString (name));
};

/* public BigInteger */org.webpki.json.JSONObjectReader.prototype.getBigInteger = function (/* String */name)
{
    return org.webpki.math.BigInteger.fromString (this._getString (name, org.webpki.json.JSONTypes.INTEGER));
};

// No real support for BigDecimal but at least text parsing is performed

/* public BigDecimal */org.webpki.json.JSONObjectReader.prototype.getBigDecimal = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.DECIMAL);
};


/* public double */org.webpki.json.JSONObjectReader.prototype.getDouble = function (/* String */name)
{
    return parseFloat (this._getString (name, org.webpki.json.JSONTypes.DOUBLE));
};

/* public org.webpki.json.JSONArrayReader */org.webpki.json.JSONObjectReader.prototype.getJSONArrayReader = function ()
{
    return this.json._isArray () ?  new org.webpki.json.JSONArrayReader (/* (Vector<org.webpki.json.JSONValue>) */this.json.property_list[0].value.value) : null;
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.getIfNULL = function (/* String */name)
{
    if (this.getPropertyType (name) == org.webpki.json.JSONTypes.NULL)
    {
        this.scanAway (name);
        return true;
    }
    return false;
};

/* public org.webpki.json.JSONObjectReader */org.webpki.json.JSONObjectReader.prototype.getObject = function (/* String */name)
{
    /* org.webpki.json.JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.OBJECT);
    return new org.webpki.json.JSONObjectReader (/* (org.webpki.json.JSONObject) */value.value);
};

/* public org.webpki.json.JSONArrayReader */org.webpki.json.JSONObjectReader.prototype.getArray = function (/* String */name)
{
    /* org.webpki.json.JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.ARRAY);
    return new org.webpki.json.JSONArrayReader (/* (Vector<org.webpki.json.JSONValue>) */value.value);
};

 /* public String */org.webpki.json.JSONObjectReader.prototype.getStringConditional = function (/* String */name, /* String */optional_default_value)
{
    if (this.hasProperty (name))
    {
        return this.getString (name);
    }
    return optional_default_value === undefined ? null : optional_default_value;
};
 
/* public boolean */org.webpki.json.JSONObjectReader.prototype.getBooleanConditional = function (/* String */name, /* boolean */optional_default_value)
{
    if (hasProperty (name))
    {
        return getBoolean (name);
    }
    return optional_default_value === undefined ? false : optional_default_value;
};

/* Uint8Array */org.webpki.json.JSONObjectReader.prototype.getBinaryConditional = function (/* String */name)
{
    return this.hasProperty (name) ? this.getBinary (name) : null;
};



/* public String[] */org.webpki.json.JSONObjectReader.prototype.getStringArrayConditional = function (/* String */name)
{
    return this.hasProperty (name) ? this.getStringArray (name) : null;
};


 /* Vector<org.webpki.json.JSONValue> */org.webpki.json.JSONObjectReader.prototype._getArray = function (/* String */name, /* org.webpki.json.JSONTypes */expected)
 {
     /* org.webpki.json.JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.ARRAY);
     /* Vector<org.webpki.json.JSONValue> */var array = /* ((Vector<org.webpki.json.JSONValue>) */value.value;
     if (array.length > 0 && array[0].type != expected)
     {
         org.webpki.json.JSONError._error ("Array type mismatch for \"" + name + "\"");
     }
     return array;
 };

/* String [] */org.webpki.json.JSONObjectReader.prototype._getSimpleArray = function (/* String */name, /* org.webpki.json.JSONTypes */expected)
{
    /* Vector<String> */var array = [] /* new Vector<String> () */;
    var in_arr = this._getArray (name, expected);
    for (var i = 0; i < in_arr.length; i++)
    {
        array[i] = in_arr[i].value;
    }
    return array;
};

/* public String[] */org.webpki.json.JSONObjectReader.prototype.getStringArray = function (/* String */name)
{
    return this._getSimpleArray (name, org.webpki.json.JSONTypes.STRING);
};
 
 /* public Vector<byte[]> */org.webpki.json.JSONObjectReader.prototype.getBinaryArray = function (/* String */name)
{
    /* Vector<byte[]> */var blobs = []/* new Vector<byte[]> () */;
    var in_arr = this.getStringArray (name);
    for (var i = 0; i < in_arr.length; i++)
    {
        blobs[i] = org.webpki.util.Base64URL.decode (in_arr[i]);
    }
     return blobs;
};


/* public String[] */org.webpki.json.JSONObjectReader.prototype.getProperties = function ()
{
    var properties = [];
    for (var i = 0; i < this.json.property_list.length; i++)
    {
        properties[i] = this.json.property_list[i].name;
    }
    return properties;
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.hasProperty = function (/* String */name)
{
    return this.json._getProperty (name) != null;
};
 
/* public org.webpki.json.JSONTypes */org.webpki.json.JSONObjectReader.prototype.getPropertyType = function (/* String */name)
{
    /* org.webpki.json.JSONValue */var value = this.json._getProperty (name);
    return value == null ? null : value.type;
};

/**
 * Read and decode JCS signature object from the current JSON object.
 * @return An object which can be used to verify keys etc.
 * @see org.webpki.json.org.webpki.json.JSONObjectWriter#setSignature(JSONSigner)
 * @throws IOException In case there is something wrong with the signature 
 */
/*
 public JSONSignatureDecoder getSignature () throws IOException
 {
 return new JSONSignatureDecoder (this);
 }

 public PublicKey getPublicKey () throws IOException
 {
 return JSONSignatureDecoder.getPublicKey (this);
 }

 public X509Certificate[] getX509CertificatePath () throws IOException
 {
 return JSONSignatureDecoder.getX509CertificatePath (this);
 }
 */

/* public void */org.webpki.json.JSONObjectReader.prototype.scanAway = function (/* String */name)
{
    this._getProperty (name, this.getPropertyType (name));
};
