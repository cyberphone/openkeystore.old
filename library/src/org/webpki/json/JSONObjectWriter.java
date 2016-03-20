/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.v8dtoa.FastDtoa;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * Creates JSON objects and performs serialization according to ES6.
 * <p>
 * Also provides built-in support for JCS (JSON Cleartext Signatures) encoding.</p>
 * 
 */
public class JSONObjectWriter implements Serializable
  {
    private static final long serialVersionUID = 1L;

    static final int STANDARD_INDENT = 2;

    public static final long MAX_SAFE_INTEGER = 9007199254740991l;
    
    static final Pattern JS_ID_PATTERN  = Pattern.compile ("[a-z,A-Z,$,_]+[a-z,A-Z,$,_,0-9]*");

    JSONObject root;

    StringBuffer buffer;
    
    int indent;
    
    boolean prettyPrint;

    boolean javaScriptMode;

    boolean htmlMode;
    
    int indentFactor;

    static String htmlVariableColor = "#008000";
    static String htmlStringColor   = "#0000C0";
    static String htmlPropertyColor = "#C00000";
    static String htmlKeywordColor  = "#606060";

    static int htmlIndent           = 4;
    
    
    /**
     * For updating already read JSON objects.
     * @param reader Existing object
     * @throws IOException For any kind of underlying error...
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

    static JSONValue setNumberAsText(String value) throws IOException
      {
        JSONArrayReader ar = JSONParser.parse ("[" + value + "]").getJSONArrayReader ();
        if (ar.array.size () != 1)
          {
            throw new IOException ("Syntax error on number: " + value);
          }
        ar.getDouble ();
        return ar.array.firstElement ();
      }

    public JSONObjectWriter setNumberAsText(String name, String value) throws IOException
      {
        return setProperty (name, setNumberAsText(value));
      }

    // This code is emulating 7.1.12.1 of the EcmaScript V6 specification.
    // The purpose is for supporting signed JSON/JavaScript objects.
    public static String es6JsonNumberSerialization (double value) throws IOException
      {
        // 1. Check for JSON compatibility.
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            throw new IOException("NaN/Infinity are not permitted in JSON");
        }

        // 2.Deal with zero separately
        if (value == 0.0) {
            return "0";
        }

        // 3. Call the DtoA algorithm crunchers
        // V8 FastDtoa can't convert all numbers, so try it first but
        // fall back to old DToA in case it fails
        String result = FastDtoa.numberToString(value);
        if (result != null) {
            return result;
        }
        StringBuilder buffer = new StringBuilder();
        DToA.JS_dtostr(buffer, DToA.DTOSTR_STANDARD, 0, value);
        return buffer.toString();
     }

    static String es6Long2NumberConversion (long value) throws IOException
      {
        if (Math.abs (value) > MAX_SAFE_INTEGER)
          {
            throw new IOException ("Integer values must not exceed " + MAX_SAFE_INTEGER + " for safe representation");
          }
        return es6JsonNumberSerialization (value);
      }

    public JSONObjectWriter setInt (String name, int value) throws IOException
      {
        return setLong (name, value);
      }

    public JSONObjectWriter setLong (String name, long value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.NUMBER, es6Long2NumberConversion (value)));
      }

    public JSONObjectWriter setDouble (String name, double value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.NUMBER, es6JsonNumberSerialization (value)));
      }

    public JSONObjectWriter setBigInteger (String name, BigInteger value) throws IOException
      {
        return setString (name, value.toString ());
      }

    static String bigDecimalToString (BigDecimal value, Integer decimals)
      {
        return (decimals == null ? value : value.setScale (decimals)).toPlainString ();
      }

    public JSONObjectWriter setBigDecimal (String name, BigDecimal value) throws IOException
      {
        return setString (name, bigDecimalToString(value, null));
      }

    public JSONObjectWriter setBigDecimal (String name, BigDecimal value, Integer decimals) throws IOException
      {
        return setString (name, bigDecimalToString(value, decimals));
      }

    public JSONObjectWriter setBoolean (String name, boolean value) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.BOOLEAN, Boolean.toString (value)));
      }

    public JSONObjectWriter setNULL (String name) throws IOException
      {
        return setProperty (name, new JSONValue (JSONTypes.NULL, "null"));
      }

    public JSONObjectWriter setDateTime (String name, Date dateTime, boolean forceUtc) throws IOException
      {
        return setString (name, ISODateTime.formatDateTime (dateTime, forceUtc));
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
        JSONObjectWriter writer = new JSONObjectWriter ();
        setProperty (name, new JSONValue (JSONTypes.OBJECT, writer.root));
        return writer;
      }

    public JSONArrayWriter setArray (String name) throws IOException
      {
        JSONArrayWriter writer = new JSONArrayWriter ();
        setProperty (name, new JSONValue (JSONTypes.ARRAY, writer.array));
        return writer;
      }

    public JSONObjectWriter setArray (String name, JSONArrayWriter writer) throws IOException
      {
        setProperty (name, new JSONValue (JSONTypes.ARRAY, writer.array));
        return this;
      }

    JSONObjectWriter setStringArray (String name, String[] values, JSONTypes jsonType) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        for (String value : values)
          {
            array.add (new JSONValue (jsonType, value));
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

    void setCurvePoint (BigInteger value, String name, KeyAlgorithms ec) throws IOException
      {
        byte[] curvePoint = value.toByteArray ();
        if (curvePoint.length > (ec.getPublicKeySizeInBits () + 7) / 8)
          {
            if (curvePoint[0] != 0)
              {
                throw new IOException ("Unexpected EC \"" + name + "\" value");
              }
            setCryptoBinary (value, name);
          }
        else
          {
            while (curvePoint.length < (ec.getPublicKeySizeInBits () + 7) / 8)
              {
                curvePoint = ArrayUtil.add (new byte[]{0}, curvePoint);
              }
            setBinary (name, curvePoint);
          }
      }

    void setCryptoBinary (BigInteger value, String name) throws IOException
      {
        byte[] cryptoBinary = value.toByteArray ();
        if (cryptoBinary[0] == 0x00)
          {
            byte[] woZero = new byte[cryptoBinary.length - 1];
            System.arraycopy (cryptoBinary, 1, woZero, 0, woZero.length);
            cryptoBinary = woZero;
          }
        setBinary (name, cryptoBinary);
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

    import org.webpki.crypto.AsymKeySignerInterface;
    import org.webpki.crypto.AsymSignatureAlgorithms;
    import org.webpki.crypto.SignatureWrapper;

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

    public void signAndVerifyJCS(final PublicKey publicKey, final PrivateKey privateKey) throws IOException {
    
      // Create an empty JSON document
      JSONObjectWriter writer = new JSONObjectWriter();
    
      // Fill it with some data
      writer.setString("myProperty", "Some data");
    
      // Sign document
      writer.setSignature(new JSONAsymKeySigner(new AsymKeySignerInterface() {
        {@literal @}Override
        public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
          try {
            return new SignatureWrapper(algorithm, privateKey).update(data).sign();
          } catch (GeneralSecurityException e) {
            throw new IOException(e);
          }
        }
        {@literal @}Override
        public PublicKey getPublicKey() throws IOException {
          return publicKey;
        }
      }));
    
      // Serialize document
      String json = writer.toString();
    
      // Print document on the console
      System.out.println("Signed doc: " + json);
    
      // Parse document
      JSONObjectReader reader = JSONParser.parse(json);
    
      // Get and verify signature
      JSONSignatureDecoder signature = reader.getSignature();
      signature.verify(new JSONAsymKeyVerifier(publicKey));
    
      // Print document payload on the console
      System.out.println("Returned data: " + reader.getString("myProperty"));
    }
</pre>
*/
    public JSONObjectWriter setSignature (JSONSigner signer) throws IOException
      {
        JSONObjectWriter signatureWriter = setObject (JSONSignatureDecoder.SIGNATURE_JSON);
        signatureWriter.setString (JSONSignatureDecoder.ALGORITHM_JSON,
                                   signer.getAlgorithm ().getAlgorithmId (signer.algorithmPreferences));
        if (signer.keyId != null)
          {
            signatureWriter.setString (JSONSignatureDecoder.KEY_ID_JSON, signer.keyId);
          }
        signer.writeKeyData (signatureWriter);
        if (signer.extensions != null)
          {
            Vector<JSONValue> array = new Vector<JSONValue> ();
            for (JSONObjectWriter jor : signer.extensions)
              {
                array.add (new JSONValue (JSONTypes.OBJECT, jor.root));
              }
            signatureWriter.setProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new JSONValue (JSONTypes.ARRAY, array));
          }
        signatureWriter.setBinary (JSONSignatureDecoder.VALUE_JSON, 
                                   signer.signData (signer.normalizedData = serializeJSONObject (JSONOutputFormats.NORMALIZED)));
        return this;
      }
    
    public JSONObjectWriter setPublicKey (PublicKey publicKey, AlgorithmPreferences algorithmPreferences) throws IOException
      {
        JSONObjectWriter publicKeyWriter = setObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm (publicKey);
        if (keyAlg.isRSAKey ())
          {
            publicKeyWriter.setString (JSONSignatureDecoder.TYPE_JSON, JSONSignatureDecoder.RSA_PUBLIC_KEY);
            RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
            publicKeyWriter.setCryptoBinary (rsaPublicKey.getModulus (), JSONSignatureDecoder.N_JSON);
            publicKeyWriter.setCryptoBinary (rsaPublicKey.getPublicExponent (), JSONSignatureDecoder.E_JSON);
          }
        else
          {
            publicKeyWriter.setString (JSONSignatureDecoder.TYPE_JSON, JSONSignatureDecoder.EC_PUBLIC_KEY);
            publicKeyWriter.setString (JSONSignatureDecoder.CURVE_JSON, keyAlg.getAlgorithmId (algorithmPreferences));
            ECPoint ecPoint = ((ECPublicKey)publicKey).getW ();
            publicKeyWriter.setCurvePoint (ecPoint.getAffineX (), JSONSignatureDecoder.X_JSON, keyAlg);
            publicKeyWriter.setCurvePoint (ecPoint.getAffineY (), JSONSignatureDecoder.Y_JSON, keyAlg);
          }
        return this;
      }

    public JSONObjectWriter setPublicKey (PublicKey publicKey) throws IOException
      {
        return setPublicKey (publicKey, AlgorithmPreferences.JOSE_ACCEPT_PREFER);
      }

    public JSONObjectWriter setCertificatePath (X509Certificate[] certificatePath) throws IOException
      {
        X509Certificate lastCertificate = null;
        Vector<byte[]> certificates = new Vector<byte[]> ();
        for (X509Certificate certificate : certificatePath)
          {
            try
              {
                certificates.add (JSONSignatureDecoder.pathCheck (lastCertificate, lastCertificate = certificate).getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        setBinaryArray (JSONSignatureDecoder.CERTIFICATE_PATH_JSON, certificates);
        return this;
      }

    void newLine ()
      {
        if (prettyPrint)
          {
            buffer.append (htmlMode ? "<br>" : "\n");
          }
      }

    void indentLine ()
      {
        indent += indentFactor;
      }

    void undentLine ()
      {
        indent -= indentFactor;
      }

    @SuppressWarnings("unchecked")
    void printOneElement (JSONValue jsonValue)
      {
        switch (jsonValue.type)
          {
            case ARRAY:
              printArray ((Vector<JSONValue>) jsonValue.value);
              break;
  
            case OBJECT:
              printObject ((JSONObject) jsonValue.value);
              break;
  
            default:
              printSimpleValue (jsonValue, false);
          }
      }

    void newUndentSpace ()
      {
        newLine ();
        undentLine ();
        spaceOut ();
      }

    void newIndentSpace ()
      {
        newLine ();
        indentLine ();
        spaceOut ();
      }

    void printObject (JSONObject object)
      {
        buffer.append ('{');
        indentLine ();
        boolean next = false;
        for (String property : object.properties.keySet ())
          {
            JSONValue jsonValue = object.properties.get (property);
            if (next)
              {
                buffer.append (',');
              }
            newLine ();
            next = true;
            printProperty (property);
            printOneElement (jsonValue);
          }
        newUndentSpace ();
        buffer.append ('}');
      }

    @SuppressWarnings("unchecked")
    void printArray (Vector<JSONValue> array)
      {
         buffer.append ('[');
         if (!array.isEmpty ())
          {
            boolean mixed = false;
            JSONTypes firstType = array.firstElement ().type;
            for (JSONValue jsonValue : array)
              {
                if (firstType.complex != jsonValue.type.complex ||
                    (firstType.complex && firstType != jsonValue.type))
                    
                  {
                    mixed = true;
                    break;
                  }
              }
            if (mixed || (array.size() == 1 && firstType == JSONTypes.OBJECT))
              {
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
            else if (firstType == JSONTypes.OBJECT)
              {
                printArrayObjects (array);
              }
            else if (firstType == JSONTypes.ARRAY)
              {
                newIndentSpace ();
                boolean next = false;
                for (JSONValue value : array)
                  {
                    Vector<JSONValue> subArray = (Vector<JSONValue>) value.value;
                    if (next)
                      {
                        buffer.append (',');
                      }
                    else
                      {
                        next = true;
                      }
                    printArray (subArray);
                  }
                newUndentSpace ();
              }
            else
              {
                printArraySimple (array);
              }
          }
        buffer.append (']');
      }

    void printArraySimple (Vector<JSONValue> array)
      {
        int i = 0;
        for (JSONValue value : array)
          {
            i += ((String)value.value).length ();
          }
        boolean brokenLines = i > 100;
        boolean next = false;
        if (brokenLines)
          {
            indentLine ();
            newLine ();
          }
        for (JSONValue value : array)
          {
            if (next)
              {
                buffer.append (',');
                if (brokenLines)
                  {
                    newLine ();
                  }
              }
            if (brokenLines)
              {
                spaceOut ();
              }
            printSimpleValue (value, false);
            next = true;
          }
        if (brokenLines)
          {
            newUndentSpace ();
          }
      }

    void printArrayObjects (Vector<JSONValue> array)
      {
        newIndentSpace ();
        boolean next = false;
        for (JSONValue value : array)
          {
            if (next)
              {
                buffer.append (',');
                newLine ();
                spaceOut ();
              }
            printObject ((JSONObject)value.value);
            next = true;
          }
        newUndentSpace ();
      }

    @SuppressWarnings("fallthrough")
    void printSimpleValue (JSONValue value, boolean property)
      {
        String string = (String) value.value;
        if (value.type != JSONTypes.STRING)
          {
            if (htmlMode)
              {
                buffer.append ("<span style=\"color:")
                      .append (htmlVariableColor)
                      .append ("\">");
              }
            buffer.append (string);
            if (htmlMode)
              {
                buffer.append ("</span>");
              }
            return;
          }
        boolean quoted = !property || !javaScriptMode || !JS_ID_PATTERN.matcher (string).matches ();
        if (htmlMode)
          {
            buffer.append ("&quot;<span style=\"color:")
                  .append (property ? string.startsWith ("@") ? htmlKeywordColor : htmlPropertyColor : htmlStringColor)
                  .append ("\">");
          }
        else if (quoted)
          {
            buffer.append ('"');
          }
        for (char c : string.toCharArray ())
          {
            if (htmlMode)
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

                case '&':
                  if (javaScriptMode)
                    {
                      buffer.append ("\\u0026");
                      break;
                    }

                case '>':
                  if (javaScriptMode)
                    {
                      buffer.append ("\\u003e");
                      break;
                    }

                case '<':
                  if (javaScriptMode)
                    {
                      buffer.append ("\\u003c");
                      break;
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
        if (htmlMode)
          {
            buffer.append ("</span>&quot;");
          }
        else if (quoted)
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
        if (prettyPrint)
          {
            if (htmlMode)
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

    @SuppressWarnings("unchecked")
    public byte[] serializeJSONObject (JSONOutputFormats outputFormat) throws IOException
      {
        buffer = new StringBuffer ();
        indentFactor = outputFormat == JSONOutputFormats.PRETTY_HTML ? htmlIndent : STANDARD_INDENT;
        prettyPrint = outputFormat.pretty;
        javaScriptMode = outputFormat.javascript;
        htmlMode = outputFormat.html;
        if (root.properties.containsKey (null))
          {
            printArray ((Vector<JSONValue>)root.properties.get (null).value);
          }
        else
          {
            printObject (root);
          }
        if (!javaScriptMode)
          {
            newLine ();
          }
        return buffer.toString ().getBytes ("UTF-8");
      }

    public String serializeToString (JSONOutputFormats format) throws IOException
      {
        return new String (serializeJSONObject (format), "UTF-8");
      }

    @Override
    public String toString ()
      {
        try
          {
            return serializeToString (JSONOutputFormats.PRETTY_PRINT);
          }
        catch (IOException e)
          {
            throw new RuntimeException (e);
          }
      }
  }
