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

import java.util.regex.Pattern;

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

    static final Pattern DECIMAL_PATTERN = Pattern.compile ("-?([1-9][0-9]+|0)[\\.][0-9]+");

    JSONObject root;

    JSONObjectReader (JSONObject root)
      {
        this.root = root;
      }

    public void checkForUnread () throws IOException
      {
        if (getJSONArrayReader () == null)
          {
            JSONObject.checkObjectForUnread (root);
          }
        else
          {
            JSONObject.checkArrayForUnread (root.properties.get (null), "Outer");
          }
      }

    JSONValue getProperty (String name, JSONTypes expected_type) throws IOException
      {
        JSONValue value = root.properties.get (name);
        if (value == null)
          {
            throw new IOException ("Property \"" + name + "\" is missing");
          }
        JSONTypes.compatibilityTest (expected_type, value);
        value.read_flag = true;
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

    static BigInteger parseBigInteger (String value) throws IOException
      {
        if (JSONParser.INTEGER_PATTERN.matcher (value).matches ())
          {
            return new BigInteger (value);
          }
        throw new IOException ("Malformed \"BigInteger\": " + value);
      }

    static BigDecimal parseBigDecimal (String value) throws IOException
      {
        if (JSONParser.INTEGER_PATTERN.matcher (value).matches () ||
            DECIMAL_PATTERN.matcher (value).matches ())
          {
            return new BigDecimal (value);
          }
        throw new IOException ("Malformed \"BigDecimal\": " + value);
      }

    public BigInteger getBigInteger (String name) throws IOException
      {
        return parseBigInteger (getString (name));
      }

    public BigDecimal getBigDecimal (String name) throws IOException
      {
        return parseBigDecimal (getString (name));
      }

    public double getDouble (String name) throws IOException
      {
        return new Double (getString (name, JSONTypes.DOUBLE));
      }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getJSONArrayReader ()
      {
        return root.properties.containsKey (null) ? new JSONArrayReader ((Vector<JSONValue>) root.properties.get (null).value) : null;
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
        return this.getStringConditional (name, null);
      }

    public boolean getBooleanConditional (String name) throws IOException
      {
        return this.getBooleanConditional (name, false);
      }

    public String getStringConditional (String name, String default_value) throws IOException
      {
        return hasProperty (name) ? getString (name) : default_value;
      }

    public boolean getBooleanConditional (String name, boolean default_value) throws IOException
      {
        return hasProperty (name) ? getBoolean (name) : default_value;
      }

    public byte[] getBinaryConditional (String name) throws IOException
      {
        return hasProperty (name) ? getBinary (name) : null;
      }

    public String[] getStringArrayConditional (String name) throws IOException
      {
        return hasProperty (name) ? getStringArray (name) : null;
      }

    String [] getSimpleArray (String name, JSONTypes expected_type) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        @SuppressWarnings("unchecked")
        Vector<JSONValue> array_elements = ((Vector<JSONValue>) getProperty (name, JSONTypes.ARRAY).value);
        for (JSONValue value : array_elements)
          {
            JSONTypes.compatibilityTest (expected_type, value);
            value.read_flag = true;
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
        return root.properties.keySet ().toArray (new String[0]);
      }

    public boolean hasProperty (String name)
      {
        return root.properties.get (name) != null;
      }

    public JSONTypes getPropertyType (String name) throws IOException
      {
        JSONValue value = root.properties.get (name);
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
