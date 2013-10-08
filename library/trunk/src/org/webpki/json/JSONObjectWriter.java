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

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.Vector;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.ISODateTime;

/**
 * Class that writes formatted JSON data to a DOM-like tree.
 * <p>
 * It also performs canonicalization when reading and writing enveloped signatures.
 * 
 */
public class JSONObjectWriter
  {
    static String canonicalization_debug_file;

    static final int STANDARD_INDENT = 2;

    JSONObject root;

    StringBuffer buffer;
    
    int indent;
    
    boolean pretty;

    boolean java_script_eol;

    boolean html_mode;
    
    int indent_factor;
    
    static String html_variable_color = "#008000";
    static String html_string_color   = "#0000C0";
    static String html_property_color = "#C00000";
    static String html_keyword_color  = "#606060";
    static int html_indent = 4;
    
    
    /**
     * To be used for updating read JSON objects.
     */
    public JSONObjectWriter (JSONObjectReader reader)
      {
        this (reader.json);
      }

    /**
     * Creates a fresh JSON object and associated writer.
     */
    public JSONObjectWriter ()
      {
        this (new JSONObject ());
      }

    JSONObjectWriter (JSONObject root)
      {
        this.root = root;
      }
    
    JSONObjectWriter addProperty (String name, JSONValue value) throws IOException
      {
        root.addProperty (name, value);
        return this;
      }

    public JSONObjectWriter setString (String name, String value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.STRING, value));
      }

    public JSONObjectWriter setInt (String name, int value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.INTEGER, Integer.toString (value)));
      }

    public JSONObjectWriter setBigInteger (String name, BigInteger value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.INTEGER, value.toString ()));
      }

    public JSONObjectWriter setBigDecimal (String name, BigDecimal value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.DECIMAL, value.toString ()));
      }

    public JSONObjectWriter setBoolean (String name, boolean value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.BOOLEAN, Boolean.toString (value)));
      }

    public JSONObjectWriter setDateTime (String name, Date t) throws IOException
      {
        return setString (name, ISODateTime.formatDateTime (t));
      }

    public JSONObjectWriter setBinary (String name, byte[] value) throws IOException 
      {
        return setString (name, getBase64 (value));
      }

    public JSONObjectWriter setObject (String name) throws IOException
      {
        JSONObject sub_object = new JSONObject ();
        addProperty (name, new JSONValue (JSONTypes.OBJECT, sub_object));
        return new JSONObjectWriter (sub_object);
      }

    public JSONObjectWriter createContainerObject (String name) throws IOException
      {
        JSONObjectWriter container = new JSONObjectWriter (new JSONObject ());
        container.addProperty (name, new JSONValue (JSONTypes.OBJECT, this.root));
        return container;
      }

    public JSONArrayWriter setArray (String name) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
        return new JSONArrayWriter (array);
      }

    JSONObjectWriter setStringArray (String name, String[] values, JSONTypes json_type) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (String value : values)
          {
            array.add (new JSONValue (json_type, value));
          }
        return addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
      }

    public JSONObjectWriter setBinaryArray (String name, Vector<byte[]> values) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (byte[] value : values)
          {
            array.add (getBase64 (value));
          }
        return setStringArray (name, array.toArray (new String[0]));
      }

    public JSONObjectWriter setStringArray (String name, String[] values) throws IOException
      {
        return setStringArray (name, values, JSONTypes.STRING);
      }

    static String getBase64 (byte[] value) throws IOException
      {
        Base64 base64_encoder = new Base64 ();
        base64_encoder.setLineBreakOn (false);
        return base64_encoder.getBase64StringFromBinary (value);
      }

    public JSONObjectWriter setSignature (JSONSigner signer) throws IOException
      {
        new JSONSignatureEncoder (signer, this);
        return this;
      }
    
    public JSONObjectWriter setPublicKey (PublicKey public_key) throws IOException
      {
        JSONSignatureEncoder.setPublicKey (this, public_key);
        return this;
      }

    public JSONObjectWriter setX509CertificatePath (X509Certificate[] certificate_path) throws IOException
      {
        JSONSignatureEncoder.setX509CertificatePath (this, certificate_path);
        return this;
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
            if (java_script_eol)
              {
                buffer.append ('\\');
              }
            if (html_mode)
              {
                buffer.append ("<br>");
              }
            buffer.append ('\n');
          }
      }

    void indentLine ()
      {
        indent += indent_factor;
      }

    void undentLine ()
      {
        indent -= indent_factor;
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
                  printSimpleValue (json_value, false);
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
            printSimpleValue (value, false);
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

    void printSimpleValue (JSONValue value, boolean property)
      {
        String string = (String) value.value;
        if (value.type != JSONTypes.STRING)
          {
            if (html_mode)
              {
                buffer.append ("<font color=\"")
                      .append (html_variable_color)
                      .append ("\">");
              }
            buffer.append (string);
            if (html_mode)
              {
                buffer.append ("</font>");
              }
            return;
          }
        if (html_mode)
          {
            buffer.append ("&quot;<font color=\"")
                  .append (property ? string.startsWith ("@") ? html_keyword_color : html_property_color : html_string_color)
                  .append ("\">");
          }
        else
          {
            buffer.append ('"');
          }
        for (char c : string.toCharArray ())
          {
            if (html_mode)
              {
                switch (c)
                  {
/* 
      HTML needs specific escapes as well...
*/
                    case '<':
                      buffer.append ("&lt;");
                      continue;
    
                    case '>':
                      buffer.append ("&gt;");
                      continue;
    
                    case '&':
                      buffer.append ("&amp;");
                      continue;

                    case '"':
                      buffer.append ("\\&quot;");
                      continue;
                  }
              }

/* 
      Since JSON supplied as a part of web-page may need additional escaping
      while JSON data as a part of a protocol needs only needs to be parsable,
      Protocol JSON only requires the following two escape sequences.
*/
            switch (c)
              {
/* 
      Since JSON supplied as a part of web-page may need additional escaping
      while JSON data as a part of a protocol needs only needs to be parsable,
      Protocol JSON only requires the following two escape sequences.
*/
                case '"':
                case '\\':
                  escapeCharacter (c);
                  break;

/*
      But we are nice and support all the traditional ASCII control characters 

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
                  if (c < 0x20)
                    {
                      escapeCharacter ('u');
                      for (int i = 0; i < 4; i++)
                        {
                          int hex = c >>> 12;
                          buffer.append ((char)(hex > 9 ? hex + 'a' - 10 : hex + '0'));
                          c <<= 4;
                        }
                      break;
                    }
                  buffer.append (c);
              }
          }
        if (html_mode)
          {
            buffer.append ("</font>&quot;");
          }
        else
          {
            buffer.append ('"');
          }
      }

    void escapeCharacter (char c)
      {
        buffer.append ('\\').append (c);
      }

    void singleSpace ()
      {
        if (pretty)
          {
            if (html_mode)
              {
                buffer.append ("&nbsp;");
              }
            else
              {
                buffer.append (' ');
              }
          }
      }

    void printProperty (String name)
      {
        spaceOut ();
        printSimpleValue (new JSONValue (JSONTypes.STRING, name), true);
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
        byte[] result = writer.serializeJSONObject (JSONOutputFormats.CANONICALIZED);
        if (canonicalization_debug_file != null)
          {
            byte[] other = ArrayUtil.readFile (canonicalization_debug_file);
            ArrayUtil.writeFile (canonicalization_debug_file,
                                 ArrayUtil.add (other, 
                                                new StringBuffer ("\n\n").append (writer.buffer).toString ().getBytes ("UTF-8")));
          }
        return result;
      }

    public byte[] serializeJSONObject (JSONOutputFormats output_format) throws IOException
      {
        buffer = new StringBuffer ();
        indent_factor = output_format == JSONOutputFormats.PRETTY_HTML ? html_indent : STANDARD_INDENT;
        indent = -indent_factor;
        pretty = output_format != JSONOutputFormats.CANONICALIZED;
        java_script_eol = output_format == JSONOutputFormats.PRETTY_JAVASCRIPT;
        html_mode = output_format == JSONOutputFormats.PRETTY_HTML;
        printObject (root, false);
        if (output_format == JSONOutputFormats.PRETTY_PRINT)
          {
            newLine ();
          }
        return buffer.toString ().getBytes ("UTF-8");
      }

    public static byte[] serializeParsedJSONDocument (JSONDecoder document, JSONOutputFormats output_format) throws IOException
      {
        return new JSONObjectWriter (document.root).serializeJSONObject (output_format);
      }
  
    public static void setCanonicalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Canonicalization Debug Output".getBytes ("UTF-8"));
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndFormat (byte[] json_utf8, JSONOutputFormats output_format) throws IOException
      {
        return new JSONObjectWriter (JSONParser.parse (json_utf8)).serializeJSONObject (output_format);
      }

    public static void main (String[] argc)
      {
        if (argc.length != 2)
          {
            System.out.println ("\nJSON-input-document format(" + JSONOutputFormats.getOptions () + ")");
            System.exit (0);
          }
        try
          {
            JSONOutputFormats format = JSONOutputFormats.getFormatFromString (argc[1]);
            String pre = "";
            String post = "";
            if (format == JSONOutputFormats.PRETTY_HTML)
              {
                pre = "<html><body>";
                post = "</body></html>";
              }
            System.out.print (pre + new String (parseAndFormat (ArrayUtil.readFile (argc[0]), format), "UTF-8") + post);
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
