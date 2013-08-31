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
import java.util.TreeSet;
import java.util.Vector;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.ISODateTime;

/**
 * Class that writes formatted JSON data to a DOM-like tree.
 * <p>
 * It also performs canonicalization when reading and writing enveloped signatures.
 * <p>
 * The current version is only intended to support the XSD-like document features
 * supported by the reading system {@link JSONDecoderCache} and {@link JSONDecoder}. 
 * 
 */
public class JSONWriter
  {
    static String canonicalization_debug_file;

    JSONObject root;

    JSONObject current;
    
    StringBuffer buffer;
    
    int indent;
    
    boolean pretty = true;
    
    boolean sort = false;
    
    public JSONWriter (String context) throws IOException
      {
        current = root = new JSONObject ();
        current.addProperty (JSONDecoderCache.CONTEXT_JSON, new JSONValue (JSONTypes.STRING, context));
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
        save.addProperty (name, new JSONValue (JSONTypes.OBJECT, holder));
        current = holder;
        json_object.writeObject (this);
        current = save;
        return holder;
      }

    public void setObjectArray (String name, JSONObjectWriter[] json_objects) throws IOException
      {
        JSONObject save = current;
        Vector<JSONValue> array = new Vector<JSONValue> ();
        save.addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
        for (JSONObjectWriter json_object : json_objects)
          {
            JSONObject holder = new JSONObject ();
            array.add (new JSONValue (JSONTypes.OBJECT, holder));
            current = holder;
            json_object.writeObject (this);
          }
        current = save;
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
        base64_encoder.setLineBreakOn (false);
        return base64_encoder.getBase64StringFromBinary (value);
      }

    public void setBinary (String name, byte[] value) throws IOException 
      {
        setString (name, getBase64 (value));
      }

    public void setEnvelopedSignature (JSONSigner signer) throws IOException
      {
        new JSONSignatureEncoder (signer, this);
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
        for (String property : sort ? new TreeSet<String> (object.properties.keySet ()).descendingSet () :  object.properties.keySet ())
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

    static byte[] getCanonicalizedSubset (JSONObject signature_object_in) throws IOException
      {
        JSONWriter writer = new JSONWriter (signature_object_in);
        writer.pretty = false;
        writer.sort = true;
        byte[] result = writer.serializeJSONStructure ();
        if (canonicalization_debug_file != null)
          {
            byte[] other = ArrayUtil.readFile (canonicalization_debug_file);
            ArrayUtil.writeFile (canonicalization_debug_file,
                                 ArrayUtil.add (other, 
                                                new StringBuffer ("\n\n").append (writer.buffer).toString ().getBytes ("UTF-8")));
          }
        return result;
      }

    public byte[] serializeJSONStructure () throws IOException
      {
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
  
    public static void setCanonicalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Canonicalization Debug Output".getBytes ("UTF-8"));
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndPrettyPrint (byte[] json_utf8) throws IOException
      {
        return new JSONWriter (new JSONParser ().parse (json_utf8)).serializeJSONStructure ();
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
