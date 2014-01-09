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
package org.webpki.json;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.GregorianCalendar;
import java.util.Vector;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * JSON object reader.
 * Returned by the parser methods.
 *
 */
public class JSONObjectReader implements Serializable
  {
    private static final long serialVersionUID = 1L;

    JSONObject json;

    JSONObjectReader (JSONObject json)
      {
        this.json = json;
      }

    JSONValue getProperty (String name, JSONTypes expected_type) throws IOException
      {
        JSONValue value = json.properties.get (name);
        if (value == null)
          {
            throw new IOException ("Property \"" + name + "\" is missing");
          }
        if (!expected_type.isCompatible (value.type))
          {
            throw new IOException ("Type mismatch for \"" + name + "\": Read=" + value.type.toString () + ", Expected=" + expected_type.toString ());
          }
        json.read_flag.add (name);
        return value;
      }

    String getString (String name, JSONTypes expected) throws IOException
      {
        JSONValue value = getProperty (name, expected);
        return (String) value.value;
      }

    public String getString (String name) throws IOException
      {
        return getString (name, JSONTypes.STRING);
      }

    public int getInt (String name) throws IOException
      {
        return Integer.parseInt (getString (name, JSONTypes.INTEGER));
      }

    public long getLong (String name) throws IOException
      {
        return Long.parseLong (getString (name, JSONTypes.INTEGER));
      }

    public boolean getBoolean (String name) throws IOException
      {
        return new Boolean (getString (name, JSONTypes.BOOLEAN));
      }

    public GregorianCalendar getDateTime (String name) throws IOException
      {
        return ISODateTime.parseDateTime (getString (name));
      }

    public byte[] getBinary (String name) throws IOException
      {
        return Base64URL.decode (getString (name));
      }

    public BigInteger getBigInteger (String name) throws IOException
      {
        return new BigInteger (getString (name, JSONTypes.INTEGER));
      }

    public BigDecimal getBigDecimal (String name) throws IOException
      {
        return new BigDecimal (getString (name, JSONTypes.DECIMAL));
      }

    public double getDouble (String name) throws IOException
      {
        return new Double (getString (name, JSONTypes.DOUBLE));
      }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getJSONArrayReader ()
      {
        return json.properties.containsKey (null) ? new JSONArrayReader ((Vector<JSONValue>) json.properties.get (null).value) : null;
      }

    public boolean getIfNULL (String name) throws IOException
      {
        if (getPropertyType (name) == JSONTypes.NULL)
          {
            scanAway (name);
            return true;
          }
        return false;
      }

    public JSONObjectReader getObject (String name) throws IOException
      {
        JSONValue value = getProperty (name, JSONTypes.OBJECT);
        return new JSONObjectReader ((JSONObject) value.value);
      }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray (String name) throws IOException
      {
        JSONValue value = getProperty (name, JSONTypes.ARRAY);
        return new JSONArrayReader ((Vector<JSONValue>) value.value);
      }

    public String getStringConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getString (name);
          }
        return null;
      }

    public boolean getBooleanConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getBoolean (name);
          }
        return false;
      }

    public byte[] getBinaryConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getBinary (name);
          }
        return null;
      }

    public String getStringConditional (String name, String default_value) throws IOException
      {
        if (hasProperty (name))
          {
            return getString (name);
          }
        return default_value;
      }

    public String[] getStringArrayConditional (String name) throws IOException
      {
        if (hasProperty (name))
          {
            return getStringArray (name);
          }
        return null;
      }

    public boolean getBooleanConditional (String name, boolean default_value) throws IOException
      {
        if (hasProperty (name))
          {
            return getBoolean (name);
          }
        return default_value;
      }

    Vector<JSONValue> getArray (String name, JSONTypes expected) throws IOException
      {
        JSONValue value = getProperty (name, JSONTypes.ARRAY);
        @SuppressWarnings("unchecked")
        Vector<JSONValue> array = ((Vector<JSONValue>) value.value);
        if (!array.isEmpty () && array.firstElement ().type != expected)
          {
            throw new IOException ("Array type mismatch for \"" + name + "\"");
          }
        return array;
      }

    String [] getSimpleArray (String name, JSONTypes expected) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (JSONValue value : getArray (name, expected))
          {
            array.add ((String)value.value);
          }
        return array.toArray (new String[0]);
      }

    public String[] getStringArray (String name) throws IOException
      {
        return getSimpleArray (name, JSONTypes.STRING);
      }

    public Vector<byte[]> getBinaryArray (String name) throws IOException
      {
        Vector<byte[]> blobs = new Vector<byte[]> ();
        for (String blob : getStringArray (name))
          {
            blobs.add (Base64URL.decode (blob));
          }
        return blobs;
      }

    public String[] getProperties ()
      {
        return json.properties.keySet ().toArray (new String[0]);
      }

    public boolean hasProperty (String name)
      {
        return json.properties.get (name) != null;
      }

    public JSONTypes getPropertyType (String name) throws IOException
      {
        JSONValue value = json.properties.get (name);
        return value == null ? null : value.type;
      }

    /**
     * Read and decode JCS signature object from the current JSON object.
     * @return An object which can be used to verify keys etc.
     * @see org.webpki.json.JSONObjectWriter#setSignature(JSONSigner)
     * @throws IOException In case there is something wrong with the signature 
     */
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

    public void scanAway (String name) throws IOException
      {
        getProperty (name, getPropertyType (name));
      }
  }
