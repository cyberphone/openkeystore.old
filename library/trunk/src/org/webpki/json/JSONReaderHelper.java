/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import java.math.BigInteger;

import java.util.GregorianCalendar;
import java.util.Vector;

import org.webpki.util.Base64;
import org.webpki.util.ISODateTime;

/**
 * Reader object that is spawned by JSONDecoder implementations.
 *
 */
public class JSONReaderHelper
  {
    JSONObject root;

    JSONObject current;

    JSONReaderHelper (JSONObject current)
      {
        this.current = current;
      }

    JSONReaderHelper createJSONReaderHelper (JSONObject current)
      {
        JSONReaderHelper new_rd = new JSONReaderHelper (current);
        new_rd.root = root;
        return new_rd;
      }

    JSONValue getProperty (String name, JSONTypes expected) throws IOException
      {
        if (current.reader.hasNext ())
          {
            String found = current.reader.next ();
            if (!name.equals (found))
              {
                throw new IOException ("Looking for \"" + name + "\" found \"" + found + "\"");
              }
            JSONValue value = current.properties.get (name);
            if (value.type != expected)
              {
                throw new IOException ("Type mismatch for \"" + name + "\": Read=" + value.type.toString () + ", Expected=" + expected.toString ());
              }
            return value;
          }
        throw new IOException ("No more properties found in object when looking for \"" + name + "\"");
      }

    static byte[] getBinaryFromBase64 (String base64) throws IOException
      {
        return new Base64().getBinaryFromBase64String (base64);
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
        return getBinaryFromBase64 (getString (name));
      }

    public BigInteger getBigInteger (String name) throws IOException
      {
        return new BigInteger (getString (name, JSONTypes.INTEGER));
      }

    public JSONReaderHelper getObject (String name) throws IOException
      {
        JSONValue value = getProperty (name, JSONTypes.OBJECT);
        return createJSONReaderHelper ((JSONObject) value.value);
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
            blobs.add (getBinaryFromBase64 (blob));
          }
        return blobs;
      }

    public JSONReaderHelper[] getObjectArray (String name) throws IOException
      {
        Vector<JSONReaderHelper> readers = new Vector<JSONReaderHelper> ();
        for (JSONValue value : getArray (name, JSONTypes.OBJECT))
          {
            readers.add (createJSONReaderHelper ((JSONObject) value.value));
          }
        return readers.toArray (new JSONReaderHelper[0]);
      }

    public String[] getProperties ()
      {
        return current.properties.keySet ().toArray (new String[0]);
      }

    public boolean hasProperty (String name)
      {
        return current.properties.get (name) != null;
      }

    public JSONTypes getPropertyType (String name) throws IOException
      {
        JSONValue value = current.properties.get (name);
        return value == null ? null : value.type;
      }

    public JSONTypes getArrayType (String name) throws IOException
      {
        JSONValue value = current.properties.get (name);
        if (value == null)
          {
            throw new IOException ("Property \"" + name + "\" does not exist in this object");
          }
        if (value.type != JSONTypes.ARRAY)
          {
            throw new IOException ("Property \"" + name + "\" is not an array");
          }
        @SuppressWarnings("unchecked")
        Vector<JSONValue> array = ((Vector<JSONValue>) value.value);
        if (array.isEmpty ())
          {
            return null;
          }
        return array.firstElement ().type;
      }

    public void scanAway (String name) throws IOException
      {
        getProperty (name, getPropertyType (name));
      }
  }
