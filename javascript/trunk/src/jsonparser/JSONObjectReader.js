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

function JSONObjectReader (/* JSONObject */ json)
{
  this.json = json;
}

/* JSONValue */ JSONObjectReader.prototype._getProperty = function (/* String */ name, /* JSONTypes */ expected_type)
{
  /* JSONValue */ var value = this.json._getProperty (name);
  if (value == null)
    {
      JSONObject.prototype.bad ("Property \"" + name + "\" is missing");
    }
  if (!expected_type.isCompatible (value.type))
    {
      JSONObject.prototype.bad ("Type mismatch for \"" + name +
                                "\": Read=" + JSONValue.prototype.getJSONTypeName (value.type) + 
                                ", Expected=" + JSONValue.prototype.getJSONTypeName (expected_type));
    }
  this.json.read_flag.name = true;
  return value;
};

/* String */ JSONObjectReader.prototype._getString = function (/* String */ name, /* JSONTypes */ expected)
{
  /* JSONValue */ var value = this._getProperty (name, expected);
  return /* (String) */ value.value;
};

/* public String */ JSONObjectReader.prototype.getString = function (/* String */ name)
{
   return this._getString (name, JSONTypes.STRING);
};

/* public int */ JSONObjectReader.prototype.getInt = function (/* String */ name)
{
    return parseInt (this._getString (name, JSONTypes.INTEGER));
};

/* public long */ JSONObjectReader.prototype.getLong = function (/* String */ name)
{
    return parseInt (this._getString (name, JSONTypes.INTEGER));
};

/* public boolean */ JSONObjectReader.prototype.getBoolean = function (/* String */ name)
{
    return this._getString (name, JSONTypes.BOOLEAN) == "true";
};

/*
    public GregorianCalendar JSONObjectReader.prototype.getDateTime (String name) throws IOException
      {
        return ISODateTime.parseDateTime (getString (name));
      }

    public byte[] JSONObjectReader.prototype.getBinary (String name) throws IOException
      {
        return Base64URL.getBinaryFromBase64URL (getString (name));
      }

    public BigInteger JSONObjectReader.prototype.getBigInteger (String name) throws IOException
      {
        return new BigInteger (_getString (name, JSONTypes.INTEGER));
      }

    public BigDecimal JSONObjectReader.prototype.getBigDecimal (String name) throws IOException
      {
        return new BigDecimal (_getString (name, JSONTypes.DECIMAL));
      }
*/
/* public double */ JSONObjectReader.prototype.getDouble = function (/* String */ name)
{
    return parseFloat (this._getString (name, JSONTypes.DOUBLE));
};

/* public JSONArrayReader */ JSONObjectReader.prototype.getJSONArrayReader = function ()
{
    return this.json.property_list.length == 1 && !this.json.property_list[0].name ? new JSONArrayReader (/* (Vector<JSONValue>) */ this.json.property_list[0].value.value) : null;
};

/* public boolean */ JSONObjectReader.prototype.getIfNULL = function (/* String */ name)
{
  if (this.getPropertyType (name) == JSONTypes.NULL)
    {
      this.scanAway (name);
      return true;
    }
  return false;
};

/* public JSONObjectReader */ JSONObjectReader.prototype.getObject = function (/* String */ name)
{
  /* JSONValue */ var value = this._getProperty (name, JSONTypes.OBJECT);
   return new JSONObjectReader (/* (JSONObject) */ value.value);
};

/* public JSONArrayReader */ JSONObjectReader.prototype.getArray = function (/* String */ name)
{
  /* JSONValue */ var value = this._getProperty (name, JSONTypes.ARRAY);
  return new JSONArrayReader (/* (Vector<JSONValue>) */ value.value);
};

/*
    public String JSONObjectReader.prototype.getStringConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getString (name);
          }
        return null;
      }

    public boolean JSONObjectReader.prototype.getBooleanConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getBoolean (name);
          }
        return false;
      }

    public byte[] JSONObjectReader.prototype.getBinaryConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getBinary (name);
          }
        return null;
      }

    public String JSONObjectReader.prototype.getStringConditional (String name, String default_value) throws IOException
      {
        if (hasProperty (name))
          {
            return getString (name);
          }
        return default_value;
      }

    public String[] JSONObjectReader.prototype.getStringArrayConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getStringArray (name);
          }
        return null;
      }

    public boolean JSONObjectReader.prototype.getBooleanConditional (String name, boolean default_value) throws IOException
      {
        if (hasProperty (name))
          {
            return getBoolean (name);
          }
        return default_value;
      }

    Vector<JSONValue> JSONObjectReader.prototype.getArray (String name, JSONTypes expected) throws IOException
      {
        JSONValue value = this._getProperty (name, JSONTypes.ARRAY);
        @SuppressWarnings("unchecked")
        Vector<JSONValue> array = ((Vector<JSONValue>) value.value);
        if (!array.isEmpty () && array.firstElement ().type != expected)
          {
            throw new IOException ("Array type mismatch for \"" + name + "\"");
          }
        return array;
      }

    String [] JSONObjectReader.prototype.getSimpleArray (String name, JSONTypes expected) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (JSONValue value : getArray (name, expected))
          {
            array.add ((String)value.value);
          }
        return array.toArray (new String[0]);
      }

    public String[] JSONObjectReader.prototype.getStringArray (String name) throws IOException
      {
        return getSimpleArray (name, JSONTypes.STRING);
      }

    public Vector<byte[]> JSONObjectReader.prototype.getBinaryArray (String name) throws IOException
      {
        Vector<byte[]> blobs = new Vector<byte[]> ();
        for (String blob : getStringArray (name))
          {
            blobs.add (Base64URL.getBinaryFromBase64URL (blob));
          }
        return blobs;
      }

    public String[] JSONObjectReader.prototype.getProperties ()
      {
        return json.properties.keySet ().toArray (new String[0]);
      }

    public boolean JSONObjectReader.prototype.hasProperty (String name)
      {
        return json.properties.get (name) != null;
      }
*/

/* public JSONTypes */ JSONObjectReader.prototype.getPropertyType = function (/* String */ name)
{
    /* JSONValue */ var value = this.json._getProperty (name);
    return value == null ? null : value.type;
};

/**
     * Read and decode JCS signature object from the current JSON object.
     * @return An object which can be used to verify keys etc.
     * @see org.webpki.json.JSONObjectWriter#setSignature(JSONSigner)
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

/* public void */ JSONObjectReader.prototype.scanAway = function (/* String */ name)
{
    this._getProperty (name, this.getPropertyType (name));
};
 
