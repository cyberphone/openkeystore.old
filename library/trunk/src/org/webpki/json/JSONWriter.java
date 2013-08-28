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

import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.ISODateTime;

/**
 * Class that writes JSON data to a DOM-like tree.
 * 
 */
public class JSONWriter
  {
    static String canonicalization_debug_file;

    JSONObject root;

    JSONObject current;
    
    JSONObject signature_info;     // Only used for reading signatures

    int buffer_at_signature_info;  //    -"-

    StringBuffer buffer;
    
    int indent;
    
    boolean pretty = true;
    
    Vector<JSONEnvelopedSignatureEncoder> signatures = new Vector<JSONEnvelopedSignatureEncoder> ();
    
    public JSONWriter (String root_property, String version) throws IOException
      {
        root = new JSONObject ();
        current = new JSONObject ();
        root.addProperty (root_property, new JSONValue (JSONTypes.OBJECT, current));
        current.addProperty (JSONDecoderCache.VERSION_JSON, new JSONValue (JSONTypes.STRING, version));
      }

    JSONWriter (JSONObject root)
      {
        this.root = root;
      }

    public void setString (String name, String value) throws IOException
      {
        current.addProperty (name, new JSONValue (JSONTypes.STRING, value));
      }

    public void setInt (String name, int value) throws IOException
      {
        current.addProperty (name, new JSONValue (JSONTypes.INTEGER, Integer.toString (value)));
      }

    public void setBigInteger (String name, BigInteger value) throws IOException
      {
        current.addProperty (name, new JSONValue (JSONTypes.INTEGER, value.toString ()));
      }

    public void setBoolean (String name, boolean value) throws IOException
      {
        current.addProperty (name, new JSONValue (JSONTypes.BOOLEAN, Boolean.toString (value)));
      }

    public void setDateTime (String name, Date t) throws IOException
      {
        setString (name, ISODateTime.formatDateTime (t));
      }

    public void setObject (String name, JSONObjectWriter json_object) throws IOException
      {
        localSetObject (name, json_object);
      }

    JSONObject localSetObject (String name, JSONObjectWriter json_object) throws IOException
      {
        JSONObject save = current;
        JSONObject holder = new JSONObject ();
        current = holder;
        json_object.writeObject (this);
        current = save;
        current.addProperty (name, new JSONValue (JSONTypes.OBJECT, holder));
        return holder;
      }

    public void setObjectArray (String name, JSONObjectWriter[] json_objects) throws IOException
      {
        JSONObject save = current;
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (JSONObjectWriter json_object : json_objects)
          {
            JSONObject holder = new JSONObject ();
            current = holder;
            json_object.writeObject (this);
            array.add (new JSONValue (JSONTypes.OBJECT, holder));
          }
        current = save;
        current.addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
      }

    void setStringArray (String name, String[] values, boolean quoted) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (String value : values)
          {
            array.add (new JSONValue (JSONTypes.STRING, value));
          }
        current.addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
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
        Iterator<JSONEnvelopedSignatureEncoder> unfinished = signatures.iterator ();
        while (unfinished.hasNext ())
          {
            unfinished.next ().sign (this);
            unfinished.remove ();
          }
        buffer = new StringBuffer ();
        indent = 0;
        printObject (root, false);
        newLine ();
        return buffer.toString ().getBytes ("UTF-8");
      }

    public static byte[] serializeParsedJSONDocument (JSONDecoder document) throws IOException
      {
        return new JSONWriter (document.root).serializeJSONStructure ();
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


    void printObject (JSONObject object, boolean array_flag)
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
            switch (json_value.type)
              {
                case INTEGER:
                case BOOLEAN:
                case STRING:
                  singleSpace ();
                  printSimpleValue (json_value);
                  break;
     
                case ARRAY:
                  @SuppressWarnings("unchecked")
                  Vector<JSONValue> array = (Vector<JSONValue>) json_value.value;
                  if (array.isEmpty ())
                    {
                      singleSpace ();
                      buffer.append ('[');
                    }
                  else if (array.firstElement ().type == JSONTypes.OBJECT)
                    {
                      printArrayObjects (array);
                    }
                  else
                    {
                      printArraySimple (array);
                    }
                  buffer.append (']');
                  break;

                case OBJECT:
                  newLine ();
                  printObject ((JSONObject) json_value.value, false);
              }
          }
        endObject ();
        if (object == signature_info)
          {
            buffer_at_signature_info = buffer.length ();
            signature_info = null;
          }
      }

    void printArraySimple (Vector<JSONValue> array)
      {
        int i = 0;
        for (JSONValue value : array)
          {
            i += ((String)value.value).length ();
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
        for (JSONValue value : array)
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
            printSimpleValue (value);
            next = true;
          }
        if (broken_lines)
          {
            undentLine ();
            newLine ();
            spaceOut ();
            undentLine ();
          }
      }

    void printArrayObjects (Vector<JSONValue> array)
      {
        boolean next = false;
        for (JSONValue value : array)
          {
            if (next)
              {
                buffer.append (',');
              }
            newLine ();
            printObject ((JSONObject)value.value, !next);
            next = true;
          }
        indent--;
      }

    void printSimpleValue (JSONValue value)
      {
        String string = (String) value.value;
        if (value.type != JSONTypes.STRING)
          {
            buffer.append (string);
            return;
          }
        buffer.append ('"');
        for (char c : string.toCharArray ())
          {
            switch (c)
              {
                case '"':
                case '\\':
                  escapeCharacter (c);
                  break;

/* "Nobody" escape slashes although it is the standard...
                  case '/':
*/

                case '\b':
                  escapeCharacter ('b');
                  break;

                case '\f':
                  escapeCharacter ('f');
                  break;

                case '\n':
                  escapeCharacter ('n');
                  break;

                case '\r':
                  escapeCharacter ('r');
                  break;

                case '\t':
                  escapeCharacter ('t');
                  break;

                default:
                  buffer.append (c);
              }
          }
        buffer.append ('"');
      }

    void escapeCharacter (char c)
      {
        buffer.append ('\\').append (c);
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

    byte[] getCanonicalizedSubset (JSONObject signature_info_in, String name, String value) throws IOException
      {
        StringBuffer save_buffer = buffer;
        int save_indent = indent;
        buffer = new StringBuffer ();
        indent = 0;
        buffer_at_signature_info = 0;
        signature_info = signature_info_in;
        pretty = false;
        findSubset (root, null, name, value);
        int length = buffer.length ();
        if (length == 0)
          {
            throw new IOException ("\"" + JSONEnvelopedSignature.REFERENCE_JSON + "\" " + name + "/" + value + " not found");
          }
        if (signature_info != null)
          {
            throw new IOException ("\"" + JSONEnvelopedSignature.REFERENCE_JSON + "\" must not point to a property that is deeper nested than \"" + JSONEnvelopedSignature.ENVELOPED_SIGNATURE_JSON + "\"");
          }
        buffer.setLength (buffer_at_signature_info);
        byte[] result = buffer.toString ().getBytes ("UTF-8");
        if (canonicalization_debug_file != null)
          {
            ArrayUtil.writeFile (canonicalization_debug_file, result);
          }
        buffer = save_buffer;
        indent = save_indent;
        pretty = true;
        return result;
      }

    @SuppressWarnings("unchecked")
    void findSubset (JSONObject json_holder, String parent, String name, String value)
      {
        for (String property_name : json_holder.properties.keySet ())
          {
            JSONValue property = json_holder.properties.get (property_name);
            if (property.type == JSONTypes.ARRAY)
              {
                for (JSONValue array_element : (Vector<JSONValue>) property.value)
                  {
                    if (array_element.type == JSONTypes.OBJECT)
                      {
                        findSubset ((JSONObject) array_element.value, null, name, value);
                      }
                  }
              }
            else if (property.type == JSONTypes.OBJECT)
              {
                findSubset ((JSONObject) property.value, property_name, name, value);
              }
            else if (property.type == JSONTypes.STRING && property_name.equals (name) && value.equals (property.value))
              {
                if (parent != null)
                  {
                    printProperty (parent);
                  }
                printObject (json_holder, false);
                break;
              }
          }
      }

    public static void setCanonicalizationDebugFile (String file)
      {
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndPrettyPrint (byte[] json_utf8) throws IOException
      {
        return new JSONWriter (new JSONParser ().parse (json_utf8)).serializeJSONStructure ();
      }

    public void setEnvelopedSignature (JSONSigner signer, String name, String value) throws IOException
      {
        signatures.add (new JSONEnvelopedSignatureEncoder (signer, this, name, value));
      }

    public static void main (String[] argc)
      {
        if (argc.length != 1)
          {
            System.out.println ("\nJSON-input-document");
            System.exit (0);
          }
        try
          {
            System.out.print (new String (parseAndPrettyPrint (ArrayUtil.readFile (argc[0])), "UTF-8"));
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
