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
 * Class that writes JSON data based on a tree.
 * 
 */
public class JSONWriter
  {
    static String canonicalization_debug_file;

    JSONHolder root;

    JSONHolder current;
    
    JSONHolder signature_info;     // Only used for reading signatures

    int buffer_at_signature_info;  //    -"-

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

    public void setDateTime (String name, Date t) throws IOException
      {
        setString (name, ISODateTime.formatDateTime (t));
      }

    public void setObject (String name, JSONObject json_object) throws IOException
      {
        localSetObject (name, json_object);
      }

    JSONHolder localSetObject (String name, JSONObject json_object) throws IOException
      {
        JSONHolder save = current;
        JSONHolder holder = new JSONHolder ();
        current = holder;
        json_object.writeObject (this);
        current = save;
        current.addProperty (name, new JSONValue (false, false, holder));
        return holder;
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
                printEscapedString ((String)json_value.value, json_value.quoted);
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
        if (object == signature_info)
          {
            buffer_at_signature_info = buffer.length ();
            signature_info = null;
          }
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
            printEscapedString (string, quoted);
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

    void printEscapedString (String value, boolean quoted)
      {
        if (quoted)
          {
            buffer.append ('"');
          }
        for (char c : value.toCharArray ())
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
          
        if (quoted)
          {
            buffer.append ('"');
          }
      }

    void escapeCharacter (char c)
      {
        buffer.append ('\\').append (c);
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

    byte[] getCanonicalizedSubset (JSONHolder signature_info_in, String name, String value) throws IOException
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
            throw new IOException ("\"" + JSONEnvelopedSignature.REFERENCE_JSON + "\" not found");
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

    public static void setCanonicalizationDebugFile (String file)
      {
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
