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

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Vector;

import org.webpki.util.Base64;

/**
 * Base class for java classes who can be translated from JSON data.
 */
public class JSONWriter
  {
    static class JSONValue
      {
        boolean simple;
        boolean quoted;
        Object value;
        
        JSONValue (boolean simple, boolean quoted, Object value)
          {
            this.simple = simple;
            this.quoted = quoted;
            this.value = value;
          }
      }

    static class JSONHolder
      {
        LinkedHashMap<String,JSONValue> properties = new LinkedHashMap<String,JSONValue> ();
        
        Iterator<String> reader;

        JSONHolder ()
          {
          }

        public void addProperty (String name, JSONValue value) throws IOException
          {
            if (properties.put (name, value) != null)
              {
                throw new IOException ("Duplicate: " + name);
              }
          }
      }

    JSONHolder root;

    JSONHolder current;

    StringBuffer buffer;
    
    int indent;
    
    boolean pretty = true;
    
    public JSONWriter (String root_proprty, String version) throws IOException
      {
        root = new JSONHolder ();
        current = new JSONHolder ();
        root.addProperty (root_proprty, new JSONValue (false, false, current));
        current.addProperty (JSONDecoderCache.VERSION_JSON, new JSONValue (true, true, version));
      }
    
    JSONWriter (JSONHolder root)
      {
        this.root = root;
      }

    public void setString (String name, String value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, true, value));
      }

    public void setInteger (String name, int value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, false, Integer.toString (value)));
      }

    public void setBigInteger (String name, BigInteger value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, false, value.toString ()));
      }

    public void setBoolean (String name, boolean value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, false, Boolean.toString (value)));
      }

    public void setObject (String name, JSONObject json_object) throws IOException
      {
        JSONHolder save = current;
        JSONHolder holder = new JSONHolder ();
        current = holder;
        json_object.writeObject (this);
        current = save;
        current.addProperty (name, new JSONValue (false, false, holder));
      }

    public void setObjectArray (String name, JSONObject[] json_objects) throws IOException
      {
        JSONHolder save = current;
        Vector<JSONHolder> array = new Vector<JSONHolder> ();
        for (JSONObject json_object : json_objects)
          {
            JSONHolder holder = new JSONHolder ();
            current = holder;
            json_object.writeObject (this);
            array.add (holder);
          }
        current = save;
        current.addProperty (name, new JSONValue (false, false, array));
      }

    void setStringArray (String name, String[] values, boolean quoted) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (String value : values)
          {
            array.add (value);
          }
        current.addProperty (name, new JSONValue (false, quoted, array));
      }

    public void setBinaryArray (String name, Vector<byte[]> values) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (byte[] value : values)
          {
            array.add (getBase64 (value));
          }
        setStringArray (name, array.toArray (new String[0]), true);
      }

    public void setStringArray (String name, String[] values) throws IOException
      {
        setStringArray (name, values, true);
      }

    static String getBase64 (byte[] value) throws IOException
      {
        Base64 base64_encoder = new Base64 ();
        base64_encoder.setPaddingOn (false);
        base64_encoder.setLineBreakOn (false);
        return base64_encoder.getBase64StringFromBinary (value);
      }

    public void setBinary (String name, byte[] value) throws IOException 
      {
        setString (name, getBase64 (value));
      }

    public byte[] serializeJSONStructure () throws IOException
      {
        buffer = new StringBuffer ();
        indent = 0;
        printObject (root, false);
        newLine ();
        return buffer.toString ().getBytes ("UTF-8");
      }
    
    void beginObject (boolean array_flag)
      {
        indentLine ();
        spaceOut ();
        if (array_flag)
          {
            indent++;
            buffer.append ('[');
          }
        buffer.append ('{');
        indentLine ();
      }

    void newLine ()
      {
        if (pretty)
          {
            buffer.append ('\n');
          }
      }

    void indentLine ()
      {
        indent += 2;
      }

    void undentLine ()
      {
        indent -= 2;
      }

    
    void endObject ()
      {
        newLine ();
        undentLine ();
        spaceOut ();
        undentLine ();
        buffer.append ('}');
      }


    void printObject (JSONHolder object, boolean array_flag)
      {
        beginObject (array_flag);
        boolean next = false;
        for (String property : object.properties.keySet ())
          {
            JSONValue json_value = object.properties.get (property);
            if (next)
              {
                buffer.append (',');
              }
            newLine ();
            next = true;
            printProperty (property);
            if (json_value.simple)
              {
                singleSpace ();
                printSimpleValue (json_value);
              }
            else if (json_value.value instanceof Vector)
              {
                if (((Vector) json_value.value).isEmpty ())
                  {
                    singleSpace ();
                    buffer.append ("[]");
                  }
                else if (((Vector) json_value.value).firstElement () instanceof JSONHolder)
                  {
                    printArrayObjects ((Vector<JSONHolder>) json_value.value);
                  }
                else
                  {
                    printArraySimple ((Vector<String>) json_value.value, json_value.quoted);
                  }
              }
            else
              {
                newLine ();
                printObject ((JSONHolder) json_value.value, false);
              }
          }
        endObject ();
      }

    void printArraySimple (Vector<String> array, boolean quoted)
      {
        int i = 0;
        for (String string : array)
          {
            i += string.length ();
          }
        boolean broken_lines = i > 100;
        boolean next = false;
        if (broken_lines)
          {
            indentLine ();
            newLine ();
            spaceOut ();
          }
        else
          {
            singleSpace ();
          }
        buffer.append ('[');
        if (broken_lines)
          {
            indentLine ();
            newLine ();
          }
        for (String string : array)
          {
            if (next)
              {
                buffer.append (',');
                if (broken_lines)
                  {
                    newLine ();
                  }
              }
            if (broken_lines)
              {
                spaceOut ();
              }
            if (quoted)
              {
                buffer.append ('"');
              }
            buffer.append (string);
            if (quoted)
              {
                buffer.append ('"');
              }
            next = true;
          }
        if (broken_lines)
          {
            undentLine ();
            newLine ();
            spaceOut ();
            undentLine ();
          }
        buffer.append (']');
      }

    void printArrayObjects (Vector<JSONHolder> array)
      {
        boolean next = false;
        for (JSONHolder element : array)
          {
            if (next)
              {
                buffer.append (',');
              }
            newLine ();
            printObject (element, !next);
            next = true;
          }
        buffer.append (']');
        indent--;
      }

    void printSimpleValue (JSONValue json_value)
      {
        if (json_value.quoted)
          {
            buffer.append ('"');
          }
        buffer.append ((String)json_value.value);
        if (json_value.quoted)
          {
            buffer.append ('"');
          }
      }

    void singleSpace ()
      {
        if (pretty)
          {
            buffer.append (' ');
          }
      }

    void printProperty (String name)
      {
        spaceOut ();
        buffer.append ('\"').append (name).append ("\":");
      }

    void spaceOut ()
      {
        for (int i = 0; i < indent; i++)
          {
            singleSpace ();
          }
      }

    public byte[] getCanonicalizedSubset (String name, String value) throws IOException
      {
        StringBuffer save_buffer = buffer;
        int save_indent = indent;
        buffer = new StringBuffer ();
        indent = 0;
        pretty = false;
        findSubset (root, null, name, value);
        int length = buffer.length ();
        if (length == 0)
          {
            throw new IOException ("Subset not found");
          }
        buffer.setLength (length -= 2);
        byte[] result = buffer.toString ().getBytes ("UTF-8");
        buffer = save_buffer;
        indent = save_indent;
        pretty = true;
        return result;
      }

    void findSubset (JSONHolder json_holder, String parent, String name, String value)
      {
        for (String property : json_holder.properties.keySet ())
          {
            JSONValue json_value = json_holder.properties.get (property);
            if (json_value.value instanceof Vector)
              {
                continue;
              }
            if (property.equals (name) && json_value.simple && json_value.quoted && value.equals (json_value.value))
              {
                if (parent != null)
                  {
                    printProperty (parent);
                  }
                printObject (json_holder, false);
                break;
              }
            if (!json_value.simple)
              {
                findSubset ((JSONHolder) json_value.value, property, name, value);
              }
          }
      }
  }
