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
public class JSONObjectWriter
  {
    static String canonicalization_debug_file;

    JSONObject root;

    StringBuffer buffer;
    
    int indent;
    
    boolean pretty = true;
    
    JSONObjectWriter (String context) throws IOException
      {
        this (new JSONObject ());
        root.addProperty (JSONDecoderCache.CONTEXT_JSON, new JSONValue (JSONTypes.STRING, context));
      }

    JSONObjectWriter (JSONObject root)
      {
        this.root = root;
      }

    public void setString (String name, String value) throws IOException
      {
        root.addProperty (name, new JSONValue (JSONTypes.STRING, value));
      }

    public void setInt (String name, int value) throws IOException
      {
        root.addProperty (name, new JSONValue (JSONTypes.INTEGER, Integer.toString (value)));
      }

    public void setBigInteger (String name, BigInteger value) throws IOException
      {
        root.addProperty (name, new JSONValue (JSONTypes.INTEGER, value.toString ()));
      }

    public void setBoolean (String name, boolean value) throws IOException
      {
        root.addProperty (name, new JSONValue (JSONTypes.BOOLEAN, Boolean.toString (value)));
      }

    public void setDateTime (String name, Date t) throws IOException
      {
        setString (name, ISODateTime.formatDateTime (t));
      }

    public JSONObjectWriter setObject (String name) throws IOException
      {
        JSONObject holder = new JSONObject ();
        root.addProperty (name, new JSONValue (JSONTypes.OBJECT, holder));
        return new JSONObjectWriter (holder);
      }

    public JSONArrayWriter setArray (String name) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        root.addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
        return new JSONArrayWriter (array);
      }

    void setStringArray (String name, String[] values, boolean quoted) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (String value : values)
          {
            array.add (new JSONValue (JSONTypes.STRING, value));
          }
        root.addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
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

    @SuppressWarnings("unchecked")
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
                case ARRAY:
                  printArray ((Vector<JSONValue>) json_value.value, false);
                  break;

                case OBJECT:
                  newLine ();
                  printObject ((JSONObject) json_value.value, false);
                  break;

                default:
                  printSimpleValue (json_value);
              }
          }
        endObject ();
      }

    @SuppressWarnings("unchecked")
    void printArray (Vector<JSONValue> array, boolean array_flag)
      {
         if (array.isEmpty ())
          {
            buffer.append ('[');
          }
        else if (array.firstElement ().type == JSONTypes.OBJECT)
          {
            printArrayObjects (array);
          }
        else if (array.firstElement ().type == JSONTypes.ARRAY)
          {
            newLine ();
            indentLine ();
            spaceOut ();
            buffer.append ('[');
            boolean next = false;
            for (JSONValue value : array)
              {
                Vector<JSONValue> sub_array = (Vector<JSONValue>) value.value;
                boolean extra_pretty = sub_array.isEmpty () ||
                                       (sub_array.firstElement ().type != JSONTypes.ARRAY &&
                                        sub_array.firstElement ().type != JSONTypes.OBJECT);
                if (next)
                  {
                    buffer.append (',');
                  }
                else
                  {
                    next = true;
                  }
                if (extra_pretty)
                  {
                    newLine ();
                    indentLine ();
                    spaceOut ();
                  }
                printArray (sub_array, true);
                if (extra_pretty)
                  {
                    undentLine ();
                  }
              }
            newLine ();
            spaceOut ();
            undentLine ();
          }
        else
          {
            printArraySimple (array, array_flag);
          }
        buffer.append (']');
      }

    void printArraySimple (Vector<JSONValue> array, boolean array_flag)
      {
        int i = 0;
        for (JSONValue value : array)
          {
            i += ((String)value.value).length ();
          }
        boolean broken_lines = i > 100;
        boolean next = false;
        if (broken_lines && !array_flag)
          {
            indentLine ();
            newLine ();
            spaceOut ();
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
            if (!array_flag)
              {
                undentLine ();
              }
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
/* 
      Since JSON supplied as a part of web-page may need additional escaping
      while JSON data as a part of a protocol needs only needs to be parsable,
      Canonical JSON only supports the following two escape sequences.
*/
                case '"':
                case '\\':
                  buffer.append ('\\');
                  break;

/*
      Removed: Redundant and potentially ambiguous

                case '/':
                case '\b':
                case '\f':
                case '\n':
                case '\r':
                case '\t':
*/
              }
            buffer.append (c);
          }
        buffer.append ('"');
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
        printSimpleValue (new JSONValue (JSONTypes.STRING, name));
        buffer.append (':');
        singleSpace ();
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
        JSONObjectWriter writer = new JSONObjectWriter (signature_object_in);
        writer.pretty = false;
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

    byte[] serializeJSONStructure () throws IOException
      {
        buffer = new StringBuffer ();
        indent = 0;
        printObject (root, false);
        newLine ();
        return buffer.toString ().getBytes ("UTF-8");
      }

    public static byte[] serializeParsedJSONDocument (JSONDecoder document) throws IOException
      {
        return new JSONObjectWriter (document.root).serializeJSONStructure ();
      }
  
    public static void setCanonicalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Canonicalization Debug Output".getBytes ("UTF-8"));
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndPrettyPrint (byte[] json_utf8, boolean canonical_mode) throws IOException
      {
        return new JSONObjectWriter (new JSONParser ().parse (json_utf8)).serializeJSONStructure ();
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
            System.out.print (new String (parseAndPrettyPrint (ArrayUtil.readFile (argc[0]), true), "UTF-8"));
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
