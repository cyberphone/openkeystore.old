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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import java.util.Date;
import java.util.Vector;

import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SKSAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * Writes formatted JSON data to a DOM-like tree.
 * <p>
 * It also performs normalization for usage with JCS (JSON Cleartext Signatures).
 * 
 */
public class JSONObjectWriter implements Serializable
  {
    private static final long serialVersionUID = 1L;

    static String normalization_debug_file;

    static final int STANDARD_INDENT = 2;

    boolean jose_algorithm_preference;
    
    JSONObject root;

    StringBuffer buffer;
    
    int indent;
    
    boolean pretty_print;

    boolean java_script_string;

    boolean html_mode;
    
    int indent_factor;

    static String html_variable_color = "#008000";
    static String html_string_color   = "#0000C0";
    static String html_property_color = "#C00000";
    static String html_keyword_color  = "#606060";
    static int html_indent = 4;
    
    
    /**
     * For updating already read JSON objects.
     * @throws IOException 
     */
    public JSONObjectWriter (JSONObjectReader reader) throws IOException
      {
        this (reader.root);
        if (reader.root.properties.containsKey (null))
          {
            throw new IOException ("You cannot update array objects");
          }
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
    
    JSONObjectWriter setProperty (String name, JSONValue value) throws IOException
      {
        root.setProperty (name, value);
        return this;
      }

    public void setupForRewrite (String name)
      {
        root.properties.put (name, null);
      }

    public JSONObjectWriter setString (String name, String value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.STRING, value));
      }

    public JSONObjectWriter setInt (String name, int value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.INTEGER, Integer.toString (value)));
      }

    public JSONObjectWriter setLong (String name, long value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.INTEGER, Long.toString (value)));
      }

    public JSONObjectWriter setDouble (String name, double value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.DOUBLE, Double.toString (value)));
      }

    public JSONObjectWriter setBigInteger (String name, BigInteger value) throws IOException
      {
        return setString (name, value.toString ());
      }

    public JSONObjectWriter setBigDecimal (String name, BigDecimal value) throws IOException
      {
        return setString (name, value.toString ());
      }

    public JSONObjectWriter setBoolean (String name, boolean value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.BOOLEAN, Boolean.toString (value)));
      }

    public JSONObjectWriter setNULL (String name) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.NULL, "null"));
      }

    public JSONObjectWriter setDateTime (String name, Date date_time, boolean force_utc) throws IOException
      {
        return setString (name, ISODateTime.formatDateTime (date_time, force_utc));
      }

    public JSONObjectWriter setBinary (String name, byte[] value) throws IOException 
      {
        return setString (name, Base64URL.encode (value));
      }

    public JSONObjectWriter setObject (String name, JSONObjectReader reader) throws IOException
      {
        setProperty (name, new JSONValue (JSONTypes.OBJECT, reader.root));
        return this;
      }

    public JSONObjectWriter setObject (String name, JSONObjectWriter writer) throws IOException
      {
        setProperty (name, new JSONValue (JSONTypes.OBJECT, writer.root));
        return this;
      }

    public JSONObjectWriter setObject (String name) throws IOException
      {
          JSONObject sub_object = new JSONObject ();
          setProperty (name, new JSONValue (JSONTypes.OBJECT, sub_object));
          return new JSONObjectWriter (sub_object);
      }

    public JSONObjectWriter createContainerObject (String name) throws IOException
      {
        JSONObjectWriter container = new JSONObjectWriter (new JSONObject ());
        container.setProperty (name, new JSONValue (JSONTypes.OBJECT, this.root));
        return container;
      }

    public JSONArrayWriter setArray (String name) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        setProperty (name, new JSONValue (JSONTypes.ARRAY, array));
        return new JSONArrayWriter (array);
      }

    JSONObjectWriter setStringArray (String name, String[] values, JSONTypes json_type) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (String value : values)
          {
            array.add (new JSONValue (json_type, value));
          }
        return setProperty (name, new JSONValue (JSONTypes.ARRAY, array));
      }

    public JSONObjectWriter setBinaryArray (String name, Vector<byte[]> values) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (byte[] value : values)
          {
            array.add (Base64URL.encode (value));
          }
        return setStringArray (name, array.toArray (new String[0]));
      }

    public JSONObjectWriter setStringArray (String name, String[] values) throws IOException
      {
        return setStringArray (name, values, JSONTypes.STRING);
      }

    /**
     * Set signature property in JSON object.
     * This is the JCS signature creation method.
     * @param signer The interface to the signing key and type
     * @return Current instance of {@link org.webpki.json.JSONObjectWriter}
     * @throws IOException In case there a problem with keys etc.
     * <br>&nbsp;<br><b>Sample Code:</b>
 <pre>
import java.io.IOException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;

       .
       .
       .

    public void signAndVerifyJCS (final PublicKey public_key, final PrivateKey private_key) throws IOException
      {
        // Create an empty JSON document
        JSONObjectWriter writer = new JSONObjectWriter ();
    
        // Fill it with some data
        writer.setString ("MyProperty", "Some data");
         
        // Sign the document
        writer.setSignature (new JSONAsymKeySigner (new AsymKeySignerInterface ()
          {
            {@literal @}Override
            public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException
              {
                try
                  {
                    Signature signature = Signature.getInstance (algorithm.getJCEName ()) ;
                    signature.initSign (private_key);
                    signature.update (data);
                    return signature.sign ();
                  }
                catch (Exception e)
                  {
                    throw new IOException (e);
                  }
              }
    
            {@literal @}Override
            public PublicKey getPublicKey () throws IOException
              {
                return public_key;
              }
          }));
          
        // Serialize the document
        byte[] json = writer.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT);
    
        // Print the signed document on the console
        System.out.println ("Signed doc:\n" + new String (json, "UTF-8"));
          
        // Parse the document
        JSONObjectReader reader = JSONParser.parse (json);
         
        // Get and verify the signature
        JSONSignatureDecoder json_signature = reader.getSignature ();
        json_signature.verify (new JSONAsymKeyVerifier (public_key));
         
        // Print the document payload on the console
        System.out.println ("Returned data: " + reader.getString ("MyProperty"));
      }
 </pre>
     */

    void setCurvePoint (BigInteger value, String name, KeyAlgorithms ec) throws IOException
      {
        byte[] curve_point = value.toByteArray ();
        if (curve_point.length > (ec.getPublicKeySizeInBits () + 7) / 8)
          {
            if (curve_point[0] != 0)
              {
                throw new IOException ("Unexpected EC \"" + name + "\" value");
              }
            setCryptoBinary (value, name);
          }
        else
          {
            while (curve_point.length < (ec.getPublicKeySizeInBits () + 7) / 8)
              {
                curve_point = ArrayUtil.add (new byte[]{0}, curve_point);
              }
            setBinary (name, curve_point);
          }
      }

    void setCryptoBinary (BigInteger value, String name) throws IOException
      {
        byte[] crypto_binary = value.toByteArray ();
        if (crypto_binary[0] == 0x00)
          {
            byte[] wo_zero = new byte[crypto_binary.length - 1];
            System.arraycopy (crypto_binary, 1, wo_zero, 0, wo_zero.length);
            crypto_binary = wo_zero;
          }
        setBinary (name, crypto_binary);
      }

    public JSONObjectWriter setSignature (JSONSigner signer) throws IOException
      {
        JSONObjectWriter signature_writer = setObject (JSONSignatureDecoder.SIGNATURE_JSON);
        signature_writer.setString (JSONSignatureDecoder.ALGORITHM_JSON, getAlgorithmID (signer.getAlgorithm ()));
        if (signer.keyId != null)
          {
            signature_writer.setString (JSONSignatureDecoder.KEY_ID_JSON, signer.keyId);
          }
        signer.writeKeyData (signature_writer.setJOSEAlgorithmPreference (jose_algorithm_preference));
        if (signer.extensions != null)
          {
            Vector<JSONValue> array = new Vector<JSONValue> ();
            for (JSONObjectWriter jor : signer.extensions)
              {
                array.add (new JSONValue (JSONTypes.OBJECT, jor.root));
              }
            signature_writer.setProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new JSONValue (JSONTypes.ARRAY, array));
          }
        signature_writer.setBinary (JSONSignatureDecoder.VALUE_JSON, signer.signData (JSONObjectWriter.getNormalizedSubset (root)));
        return this;
      }
    
    String getAlgorithmID (SKSAlgorithms algorithm)
      {
        if (jose_algorithm_preference && algorithm.getJOSEName () != null)
          {
            return algorithm.getJOSEName ();
          }
        return algorithm.getURI ();
      }
 
    public JSONObjectWriter setJOSEAlgorithmPreference (boolean on)
      {
        jose_algorithm_preference = on;
        return this;
      }

    public JSONObjectWriter setPublicKey (PublicKey public_key) throws IOException
      {
        
        JSONObjectWriter public_key_writer = setObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
        if (key_alg.isRSAKey ())
          {
            public_key_writer.setString (JSONSignatureDecoder.TYPE_JSON, JSONSignatureDecoder.RSA_PUBLIC_KEY);
            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
            public_key_writer.setCryptoBinary (rsa_public.getModulus (), JSONSignatureDecoder.N_JSON);
            public_key_writer.setCryptoBinary (rsa_public.getPublicExponent (), JSONSignatureDecoder.E_JSON);
          }
        else
          {
            public_key_writer.setString (JSONSignatureDecoder.TYPE_JSON, JSONSignatureDecoder.EC_PUBLIC_KEY);
            public_key_writer.setString (JSONSignatureDecoder.CURVE_JSON, this.getAlgorithmID (key_alg));
            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
            public_key_writer.setCurvePoint (ec_point.getAffineX (), JSONSignatureDecoder.X_JSON, key_alg);
            public_key_writer.setCurvePoint (ec_point.getAffineY (), JSONSignatureDecoder.Y_JSON, key_alg);
          }
        return this;
      }

    public JSONObjectWriter setCertificatePath (X509Certificate[] certificate_path) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<byte[]> certificates = new Vector<byte[]> ();
        for (X509Certificate certificate : certificate_path)
          {
            try
              {
                certificates.add (JSONSignatureDecoder.pathCheck (last_certificate, last_certificate = certificate).getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        setBinaryArray (JSONSignatureDecoder.CERTIFICATE_PATH_JSON, certificates);
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
        if (pretty_print)
          {
            buffer.append (html_mode ? "<br>" : java_script_string ? "\\\n" : "\n");
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
    void printOneElement (JSONValue json_value)
      {
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

    void printObject (JSONObject object, boolean array_flag)
      {
        beginObject (array_flag);
        boolean next = false;
        for (String property : object.properties.keySet ())
          {
            JSONValue json_value = object.properties.get (property);
            if (json_value == null) // See JSONSignatureDecoder...
              {
                continue;
              }
            if (next)
              {
                buffer.append (',');
              }
            newLine ();
            next = true;
            printProperty (property);
            printOneElement (json_value);
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
        else
          {
            boolean mixed = false;
            JSONTypes first_type = array.firstElement ().type;
            for (JSONValue json_value : array)
              {
                if (first_type.complex != json_value.type.complex ||
                    (first_type.complex && first_type != json_value.type))
                    
                  {
                    mixed = true;
                    break;
                  }
              }
            if (mixed)
              {
                buffer.append ('[');
                boolean next = false;
                for (JSONValue value : array)
                  {
                    if (next)
                      {
                        buffer.append (',');
                      }
                    else
                      {
                        next = true;
                      }
                    printOneElement (value);
                  }
              }
            else if (first_type == JSONTypes.OBJECT)
              {
                printArrayObjects (array);
              }
            else if (first_type == JSONTypes.ARRAY)
              {
                newLine ();
                indentLine ();
                spaceOut ();
                buffer.append ('[');
                boolean next = false;
                for (JSONValue value : array)
                  {
                    Vector<JSONValue> sub_array = (Vector<JSONValue>) value.value;
                    boolean extra_pretty = sub_array.isEmpty () || !sub_array.firstElement ().type.complex;
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

    @SuppressWarnings("fallthrough")
    void printSimpleValue (JSONValue value, boolean property)
      {
        String string = (String) value.value;
        if (value.type != JSONTypes.STRING)
          {
            if (html_mode)
              {
                buffer.append ("<span style=\"color:")
                      .append (html_variable_color)
                      .append ("\">");
              }
            buffer.append (string);
            if (html_mode)
              {
                buffer.append ("</span>");
              }
            return;
          }
        if (html_mode)
          {
            buffer.append ("&quot;<span style=\"color:")
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
      HTML needs specific escapes...
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

            switch (c)
              {
                case '\\':
                  if (java_script_string)
                    {
                      // JS escaping need \\\\ in order to produce a JSON \\
                      buffer.append ('\\');
                    }

                case '"':
                  escapeCharacter (c);
                  break;

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
                  
                case '\'':
                  if (java_script_string)
                    {
                      // Since we assumed that the JSON object was enclosed between '' we need to escape ' as well
                      buffer.append ('\\');
                    }

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
            buffer.append ("</span>&quot;");
          }
        else
          {
            buffer.append ('"');
          }
      }

    void escapeCharacter (char c)
      {
        if (java_script_string)
          {
            buffer.append ('\\');
          }
        buffer.append ('\\').append (c);
      }

    void singleSpace ()
      {
        if (pretty_print)
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

    static byte[] getNormalizedSubset (JSONObject json_object) throws IOException
      {
        JSONObjectWriter writer = new JSONObjectWriter (json_object);
        byte[] result = writer.serializeJSONObject (JSONOutputFormats.NORMALIZED);
        if (normalization_debug_file != null)
          {
            byte[] other = ArrayUtil.readFile (normalization_debug_file);
            ArrayUtil.writeFile (normalization_debug_file,
                                 ArrayUtil.add (other, 
                                                new StringBuffer ("\n\n").append (writer.buffer).toString ().getBytes ("UTF-8")));
          }
        return result;
      }

    @SuppressWarnings("unchecked")
    public byte[] serializeJSONObject (JSONOutputFormats output_format) throws IOException
      {
        buffer = new StringBuffer ();
        indent_factor = output_format == JSONOutputFormats.PRETTY_HTML ? html_indent : STANDARD_INDENT;
        indent = -indent_factor;
        pretty_print = output_format.pretty;
        java_script_string = output_format.javascript;
        html_mode = output_format.html;
        if (java_script_string)
          {
            buffer.append ('\'');
          }
        if (root.properties.containsKey (null))
          {
            printArray ((Vector<JSONValue>)root.properties.get (null).value, false);
          }
        else
          {
            printObject (root, false);
          }
        if (output_format == JSONOutputFormats.PRETTY_PRINT)
          {
            newLine ();
          }
        else if (java_script_string)
          {
            buffer.append ('\'');
          }
        return buffer.toString ().getBytes ("UTF-8");
      }

    public static byte[] serializeParsedJSONDocument (JSONDecoder document, JSONOutputFormats output_format) throws IOException
      {
        return new JSONObjectWriter (document.root).serializeJSONObject (output_format);
      }
  
    public static void setNormalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Normalization Debug Output".getBytes ("UTF-8"));
        normalization_debug_file = file;
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
