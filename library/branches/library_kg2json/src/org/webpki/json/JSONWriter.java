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

    class JSONHolder
      {
        LinkedHashMap<String,JSONValue> properties = new LinkedHashMap<String,JSONValue> ();

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
    
    public JSONWriter (String top_element, String version) throws IOException
      {
        root = new JSONHolder ();
        current = new JSONHolder ();
        root.addProperty (top_element, new JSONValue (false, false, current));
        current.addProperty ("VERSION", new JSONValue (true, true, version));
      }

    public void setString (String name, String value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, true, value));
      }

    public void setInt (String name, int value) throws IOException
      {
        current.addProperty (name, new JSONValue (true, false, Integer.toString (value)));
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

    public void setBoolean (String name, boolean value)
      {
        // TODO Auto-generated method stub
        
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

    public void getParent ()
      {
        // TODO Auto-generated method stub
        
      }

    public byte[] serializeJSONStructure () throws IOException
      {
        buffer = new StringBuffer ();
        indent = 0;
        printObject (root, false);
        return buffer.append ('\n').toString ().getBytes ("UTF-8");
      }
    
    private void beginObject (boolean array_flag)
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
    private void newLine ()
      {
        if (pretty)
          {
            buffer.append ('\n');
          }
      }

    private void indentLine ()
      {
        indent += 2;
      }

    private void undentLine ()
      {
        indent -= 2;
      }

    
    private void endObject ()
      {
        newLine ();
        undentLine ();
        spaceOut ();
        undentLine ();
        buffer.append ('}');
      }


    private void printObject (JSONHolder object, boolean array_flag)
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
                Vector<JSONHolder> array = (Vector<JSONHolder>) json_value.value;
                if (array.isEmpty ())
                  {
                    singleSpace ();
                    buffer.append ("[]");
                  }
                else
                  {
                    boolean array_next = false;
                    for (JSONHolder element : array)
                      {
                        if (array_next)
                          {
                            buffer.append (',');
                          }
                        newLine ();
                        printObject (element, !array_next);
                        array_next = true;
                      }
                    buffer.append (']');
                    indent--;
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

    private void printSimpleValue (JSONValue json_value)
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

    private void singleSpace ()
      {
        if (pretty)
          {
            buffer.append (' ');
          }
      }

    private void printProperty (String name)
      {
        spaceOut ();
        buffer.append ('\"').append (name).append ("\":");
      }

    private void spaceOut ()
      {
        for (int i = 0; i < indent; i++)
          {
            singleSpace ();
          }
      }

    public void addElement (String name)
      {
        // TODO Auto-generated method stub
        
      }

    public void setList (String name, String[] values)
      {
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

    private void findSubset (JSONHolder json_holder, String parent, String name, String value)
      {
        for (String property : json_holder.properties.keySet ())
          {
            JSONValue json_value = json_holder.properties.get (property);
            if (json_value.value instanceof Vector)
              {
                continue;
              }
            if (property.equals (name) && json_value.simple && value.equals (json_value.value))
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
