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
    public enum JSON {SIMPLE,SIMPLE_QUOTED,OBJECT,SIMPLE_ARRAY,SIMPLE_QUOTED_ARRAY, OBJECT_ARRAY};

    JSONHolder root;

    JSONHolder current;

    JSONReaderHelper (JSONHolder current)
      {
        this.current = current;
      }

    JSONReaderHelper createJSONReaderHelper (JSONHolder current)
      {
        JSONReaderHelper new_rd = new JSONReaderHelper (current);
        new_rd.root = root;
        return new_rd;
      }

    JSONValue getProperty (String name) throws IOException
      {
        if (current.reader.hasNext ())
          {
            String found = current.reader.next ();
            if (!name.equals (found))
              {
                throw new IOException ("Looking for \"" + name + "\" found \"" + found + "\"");
              }
            return current.properties.get (name);
          }
        throw new IOException ("No more properties found in object when looking for \"" + name + "\"");
      }

    static byte[] getBinaryFromBase64 (String base64) throws IOException
      {
        return new Base64().getBinaryFromBase64String (base64);
      }

    void quoteTest (boolean found, boolean expected, String name) throws IOException
      {
        if (found != expected)
          {
            throw new IOException ((expected ? "Quotes missing for \"" : "Unexpected quoting for \"") + name + "\" argument");
          }
      }

    String getString (String name, boolean quoted) throws IOException
      {
        JSONValue value = getProperty (name);
        if (!value.simple)
          {
            throw new IOException ("Simple element expected for \"" + name + "\"");
          }
        quoteTest (value.quoted, quoted, name);
        return (String) value.value;
      }

    public String getString (String name) throws IOException
      {
        return getString (name, true);
      }

    public int getInt (String name) throws IOException
      {
        return Integer.parseInt (getString (name, false));
      }

    public boolean getBoolean (String name) throws IOException
      {
        String bool = getString (name, false);
        if (bool.equals ("true"))
          {
            return true;
          }
        else if (bool.equals ("false"))
          {
            return false;
          }
        throw new IOException ("Malformed boolean: " + bool);
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
        return new BigInteger (getString (name, false));
      }

    public JSONReaderHelper getObject (String name) throws IOException
      {
        JSONValue value = getProperty (name);
        if (value.simple && !(value.value instanceof JSONHolder))
          {
            throw new IOException ("\"" + name + "\" is not a JSON object");
          }
        return createJSONReaderHelper ((JSONHolder) value.value);
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

    Vector<Object> getArray (String name, boolean quoted, boolean simple_array) throws IOException
      {
        JSONValue value = getProperty (name);
        if (value.simple && !(value.value instanceof Vector))
          {
            throw new IOException ("\"" + name + "\" is not an array");
          }
        Vector<Object> array = ((Vector<Object>) value.value);
        if (!array.isEmpty ())
          {
            if (simple_array)
              {
                if (!(array.firstElement () instanceof String))
                  {
                    throw new IOException ("\"" + name + "\" is not a simple array");
                  }
                quoteTest (value.quoted, quoted, name);
              }
            else
              {
                if (!(array.firstElement () instanceof JSONHolder))
                  {
                    throw new IOException ("\"" + name + "\" is not an object array");
                  }
              }
          }
        return array;
      }

    String [] getSimpleArray (String name, boolean quoted) throws IOException
      {
        Vector<Object> array = getArray (name, quoted, true);
        return array.toArray (new String[0]);
      }

    public String[] getStringArray (String name) throws IOException
      {
        return getSimpleArray (name, true);
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
        for (Object json_object: getArray (name, false, false))
          {
            readers.add (createJSONReaderHelper ((JSONHolder) json_object));
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

    public JSON getPropertyType (String name) throws IOException
      {
        JSONValue value = current.properties.get (name);
        if (value == null)
          {
            return null;
          }
        if (value.simple)
          {
            return value.quoted ? JSON.SIMPLE_QUOTED : JSON.SIMPLE;
          }
        if (value.value instanceof JSONHolder)
          {
            return JSON.OBJECT;
          }
        Vector<Object> array = (Vector<Object>) value.value;
        if (array.isEmpty () || array.firstElement () instanceof String)
          {
            return value.quoted ? JSON.SIMPLE_QUOTED_ARRAY : JSON.SIMPLE_ARRAY;
          }
        return JSON.OBJECT_ARRAY;
      }

    public void scanAway (String name) throws IOException
      {
        getProperty (name);
      }
  }
