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
/*                        webpki.org.json.JSONObjectReader                        */
/*================================================================*/

/*================================================================*/
/*                        JSONObjectReader                        */
/*================================================================*/

 webpki.org.json.JSONObjectReader = function (/* webpki.org.json.JSONObject */json)
{
    this.json = json;
};

/* webpki.org.json.JSONValue */webpki.org.json.JSONObjectReader.prototype._getProperty = function (/* String */name, /* webpki.org.json.JSONTypes */expected_type)
{
    /* webpki.org.json.JSONValue */var value = this.json._getProperty (name);
    if (value == null)
    {
        webpki.org.json.JSONObject._error ("Property \"" + name + "\" is missing");
    }
    if (!expected_type.isCompatible (value.type))
    {
        webpki.org.json.JSONObject._error ("Type mismatch for \"" + name +
                           "\": Read=" + webpki.org.json.JSONValue.prototype.getJSONTypeName (value.type) +
                           ", Expected=" + webpki.org.json.JSONValue.prototype.getJSONTypeName (expected_type));
    }
    this.json.read_flag.name = true;
    return value;
};

/* String */webpki.org.json.JSONObjectReader.prototype._getString = function (/* String */name, /* webpki.org.json.JSONTypes */expected)
{
    /* webpki.org.json.JSONValue */var value = this._getProperty (name, expected);
    return /* (String) */value.value;
};

/* public String */webpki.org.json.JSONObjectReader.prototype.getString = function (/* String */name)
{
    return this._getString (name, webpki.org.json.JSONTypes.STRING);
};

/* public int */webpki.org.json.JSONObjectReader.prototype.getInt = function (/* String */name)
{
    return parseInt (this._getString (name, webpki.org.json.JSONTypes.INTEGER));
};

/* public long */webpki.org.json.JSONObjectReader.prototype.getLong = function (/* String */name)
{
    return parseInt (this._getString (name, webpki.org.json.JSONTypes.INTEGER));
};

/* public boolean */webpki.org.json.JSONObjectReader.prototype.getBoolean = function (/* String */name)
{
    return this._getString (name, webpki.org.json.JSONTypes.BOOLEAN) == "true";
};

/*
 public GregorianCalendar webpki.org.json.JSONObjectReader.prototype.getDateTime (String name) throws IOException
 {
 return ISODateTime.parseDateTime (getString (name));
 }

 public byte[] webpki.org.json.JSONObjectReader.prototype.getBinary (String name) throws IOException
 {
 return Base64URL.getBinaryFromBase64URL (getString (name));
 }

 public BigInteger webpki.org.json.JSONObjectReader.prototype.getBigInteger (String name) throws IOException
 {
 return new BigInteger (_getString (name, webpki.org.json.JSONTypes.INTEGER));
 }

 public BigDecimal webpki.org.json.JSONObjectReader.prototype.getBigDecimal (String name) throws IOException
 {
 return new BigDecimal (_getString (name, webpki.org.json.JSONTypes.DECIMAL));
 }
 */

/* public double */webpki.org.json.JSONObjectReader.prototype.getDouble = function (/* String */name)
{
    return parseFloat (this._getString (name, webpki.org.json.JSONTypes.DOUBLE));
};

/* public webpki.org.json.JSONArrayReader */webpki.org.json.JSONObjectReader.prototype.getJSONArrayReader = function ()
{
    return this.json._isArray () ?  new webpki.org.json.JSONArrayReader (/* (Vector<webpki.org.json.JSONValue>) */this.json.property_list[0].value.value) : null;
};

/* public boolean */webpki.org.json.JSONObjectReader.prototype.getIfNULL = function (/* String */name)
{
    if (this.getPropertyType (name) == webpki.org.json.JSONTypes.NULL)
    {
        this.scanAway (name);
        return true;
    }
    return false;
};

/* public webpki.org.json.JSONObjectReader */webpki.org.json.JSONObjectReader.prototype.getObject = function (/* String */name)
{
    /* webpki.org.json.JSONValue */var value = this._getProperty (name, webpki.org.json.JSONTypes.OBJECT);
    return new webpki.org.json.JSONObjectReader (/* (webpki.org.json.JSONObject) */value.value);
};

/* public webpki.org.json.JSONArrayReader */webpki.org.json.JSONObjectReader.prototype.getArray = function (/* String */name)
{
    /* webpki.org.json.JSONValue */var value = this._getProperty (name, webpki.org.json.JSONTypes.ARRAY);
    return new webpki.org.json.JSONArrayReader (/* (Vector<webpki.org.json.JSONValue>) */value.value);
};

/*
 public String webpki.org.json.JSONObjectReader.prototype.getStringConditional (String name) throws IOException
 {
 if (hasProperty (name))
 {
 return getString (name);
 }
 return null;
 }

 public boolean webpki.org.json.JSONObjectReader.prototype.getBooleanConditional (String name) throws IOException
 {
 if (hasProperty (name))
 {
 return getBoolean (name);
 }
 return false;
 }

 public byte[] webpki.org.json.JSONObjectReader.prototype.getBinaryConditional (String name) throws IOException
 {
 if (hasProperty (name))
 {
 return getBinary (name);
 }
 return null;
 }

 public String webpki.org.json.JSONObjectReader.prototype.getStringConditional (String name, String default_value) throws IOException
 {
 if (hasProperty (name))
 {
 return getString (name);
 }
 return default_value;
 }

 public String[] webpki.org.json.JSONObjectReader.prototype.getStringArrayConditional (String name) throws IOException
 {
 if (hasProperty (name))
 {
 return getStringArray (name);
 }
 return null;
 }

 public boolean webpki.org.json.JSONObjectReader.prototype.getBooleanConditional (String name, boolean default_value) throws IOException
 {
 if (hasProperty (name))
 {
 return getBoolean (name);
 }
 return default_value;
 }

 Vector<webpki.org.json.JSONValue> webpki.org.json.JSONObjectReader.prototype.getArray (String name, webpki.org.json.JSONTypes expected) throws IOException
 {
 webpki.org.json.JSONValue value = this._getProperty (name, webpki.org.json.JSONTypes.ARRAY);
 @SuppressWarnings("unchecked")
 Vector<webpki.org.json.JSONValue> array = ((Vector<webpki.org.json.JSONValue>) value.value);
 if (!array.isEmpty () && array.firstElement ().type != expected)
 {
 throw new IOException ("Array type mismatch for \"" + name + "\"");
 }
 return array;
 }

 String [] webpki.org.json.JSONObjectReader.prototype.getSimpleArray (String name, webpki.org.json.JSONTypes expected) throws IOException
 {
 Vector<String> array = new Vector<String> ();
 for (webpki.org.json.JSONValue value : getArray (name, expected))
 {
 array.add ((String)value.value);
 }
 return array.toArray (new String[0]);
 }

 public String[] webpki.org.json.JSONObjectReader.prototype.getStringArray (String name) throws IOException
 {
 return getSimpleArray (name, webpki.org.json.JSONTypes.STRING);
 }

 public Vector<byte[]> webpki.org.json.JSONObjectReader.prototype.getBinaryArray (String name) throws IOException
 {
 Vector<byte[]> blobs = new Vector<byte[]> ();
 for (String blob : getStringArray (name))
 {
 blobs.add (Base64URL.getBinaryFromBase64URL (blob));
 }
 return blobs;
 }

 public String[] webpki.org.json.JSONObjectReader.prototype.getProperties ()
 {
 return json.properties.keySet ().toArray (new String[0]);
 }

 public boolean webpki.org.json.JSONObjectReader.prototype.hasProperty (String name)
 {
 return json.properties.get (name) != null;
 }
 */

/* public webpki.org.json.JSONTypes */webpki.org.json.JSONObjectReader.prototype.getPropertyType = function (/* String */name)
{
    /* webpki.org.json.JSONValue */var value = this.json._getProperty (name);
    return value == null ? null : value.type;
};

/**
 * Read and decode JCS signature object from the current JSON object.
 * @return An object which can be used to verify keys etc.
 * @see org.webpki.json.webpki.org.json.JSONObjectWriter#setSignature(JSONSigner)
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

/* public void */webpki.org.json.JSONObjectReader.prototype.scanAway = function (/* String */name)
{
    this._getProperty (name, this.getPropertyType (name));
};
