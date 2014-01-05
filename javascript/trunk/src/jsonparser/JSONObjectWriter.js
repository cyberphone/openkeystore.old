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

/*================================================================*/
/*                        JSONObjectWriter                        */
/*================================================================*/

function JSONObjectWriter (/* optional argument */optional_object_or_reader)
{
    /* int */this.STANDARD_INDENT = 2;

    /* JSONObject */this.root = null;

    /* StringBuffer */this.buffer = null;
    
    /* int */this.indent = 0;
    
    /* boolean */this.pretty_print = true;

    /* boolean */this.java_script_string = false;

    /* boolean */this.html_mode = false;
    
    /* int */this.indent_factor = 0;

    /* boolean */this.xml_dsig_named_curve = false;
    
    /* static String */this.html_variable_color = "#008000";
    /* static String */this.html_string_color   = "#0000C0";
    /* static String */this.html_property_color = "#C00000";
    /* static String */this.html_keyword_color  = "#606060";
    /* static int */this.html_indent = 4;
    if (optional_object_or_reader === undefined)
    {
        this.root = new JSONObject ();
    }
    else if (optional_object_or_reader instanceof JSONObject)
    {
        this.root = optional_object_or_reader;
    }
    else if (optional_object_or_reader instanceof JSONObjectReader)
    {
        this.root = optional_object_or_reader.json;
        if (this.root.property_list.length = 1 && !this.root.property_list[0].name)
        {
            JSONObject.prototype.bad ("You cannot update array objects");
        }
    }
    else
    {
        JSONObject.prototype.bad ("Wrong init of JSONObjectWriter");
    }
}
    
/* JSONObjectWriter */JSONObjectWriter.prototype._addProperty = function (/* String */name, /* JSONValue */value)
{
    this.root._addProperty (name, value);
    return this;
};

/*
    public void setupForRewrite (String name)
      {
        root.properties.put (name, null);
      }
*/

/* public JSONObjectWriter */ JSONObjectWriter.prototype.setString = function (/* String */name, /* String */value)
{
    if (typeof value != "string")
    {
        JSONObject.prototype.bad ("Bad string: " + name);
    }
    return this._addProperty (name, new JSONValue (JSONTypes.STRING, value));
};

/* public JSONObjectWriter */JSONObjectWriter.prototype.setInt = function (/* String */name, /* int */value)
{
    var int_string = value.toString ();
    if (typeof value != "number" || int_string.indexOf ('.') >= 0)
    {
        JSONObject.prototype.bad ("Bad integer: " + name);
    }
    return this._addProperty (name, new JSONValue (JSONTypes.INTEGER, int_string));
};

/*
    public JSONObjectWriter setLong (String name, long value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.INTEGER, Long.toString (value)));
      }

    public JSONObjectWriter setDouble (String name, double value) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.DOUBLE, Double.toString (value)));
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

    public JSONObjectWriter setNULL (String name) throws IOException
      {
        return addProperty (name, new JSONValue (JSONTypes.NULL, "null"));
      }

    public JSONObjectWriter setDateTime (String name, Date date_time) throws IOException
      {
        return setString (name, ISODateTime.formatDateTime (date_time));
      }

    public JSONObjectWriter setBinary (String name, byte[] value) throws IOException 
      {
        return setString (name, Base64URL.getBase64URLFromBinary (value));
      }
*/

/* public JSONObjectWriter */JSONObjectWriter.prototype.setObject = function (/*String */name)
{
    /* JSONObject */ var sub_object = new JSONObject ();
    this._addProperty (name, new JSONValue (JSONTypes.OBJECT, sub_object));
    return new JSONObjectWriter (sub_object);
};

/*
    public JSONObjectWriter createContainerObject (String name) throws IOException
      {
        JSONObjectWriter container = new JSONObjectWriter (new JSONObject ());
        container.addProperty (name, new JSONValue (JSONTypes.OBJECT, this.root));
        return container;
      }
*/

/* public JSONArrayWriter */JSONObjectWriter.prototype.setArray = function (/* String */name)
{
        /* Vector<JSONValue> */var array = [] /* new Vector<JSONValue> ()*/;
    this._addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
    return new JSONArrayWriter (array);
};

/*
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
            array.add (Base64URL.getBase64URLFromBinary (value));
          }
        return setStringArray (name, array.toArray (new String[0]));
      }

    public JSONObjectWriter setStringArray (String name, String[] values) throws IOException
      {
        return setStringArray (name, values, JSONTypes.STRING);
      }
*/

    /**
     * Set signature property in JSON object.
     * This is the JCS signature creation method.
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

/*
    void writeCryptoBinary (BigInteger value, String name) throws IOException
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
        signature_writer.setString (JSONSignatureDecoder.ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
        signer.writeKeyInfoData (signature_writer.setObject (JSONSignatureDecoder.KEY_INFO_JSON).setXMLDSigECCurveOption (xml_dsig_named_curve));
        if (signer.extensions != null)
          {
            Vector<JSONValue> array = new Vector<JSONValue> ();
            for (JSONObjectWriter jor : signer.extensions)
              {
                array.add (new JSONValue (JSONTypes.OBJECT, jor.root));
              }
            signature_writer.addProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new JSONValue (JSONTypes.ARRAY, array));
          }
        signature_writer.setBinary (JSONSignatureDecoder.SIGNATURE_VALUE_JSON, signer.signData (JSONObjectWriter.getCanonicalizedSubset (root)));
        return this;
      }
    
    public JSONObjectWriter setPublicKey (PublicKey public_key) throws IOException
      {
        JSONObjectWriter public_key_writer = setObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
        if (key_alg.isRSAKey ())
          {
            JSONObjectWriter rsa_key_writer = public_key_writer.setObject (JSONSignatureDecoder.RSA_JSON);
            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
            rsa_key_writer.writeCryptoBinary (rsa_public.getModulus (), JSONSignatureDecoder.MODULUS_JSON);
            rsa_key_writer.writeCryptoBinary (rsa_public.getPublicExponent (), JSONSignatureDecoder.EXPONENT_JSON);
          }
        else
          {
            JSONObjectWriter ec_key_writer = public_key_writer.setObject (JSONSignatureDecoder.EC_JSON);
            ec_key_writer.setString (JSONSignatureDecoder.NAMED_CURVE_JSON, xml_dsig_named_curve ?
               KeyAlgorithms.XML_DSIG_CURVE_PREFIX + key_alg.getECDomainOID () : key_alg.getURI ());
            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
            ec_key_writer.writeCryptoBinary (ec_point.getAffineX (), JSONSignatureDecoder.X_JSON);
            ec_key_writer.writeCryptoBinary (ec_point.getAffineY (), JSONSignatureDecoder.Y_JSON);
          }
        return this;
      }

    public JSONObjectWriter setXMLDSigECCurveOption (boolean flag)
      {
        xml_dsig_named_curve = flag;
        return this;
      }

    public JSONObjectWriter setX509CertificatePath (X509Certificate[] certificate_path) throws IOException
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
        setBinaryArray (JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON, certificates);
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
            buffer.append (html_mode ? "<br>" : "\n");
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
//
//      HTML needs specific escapes...
//
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

    @SuppressWarnings("unchecked")
    public byte[] serializeJSONObject (JSONOutputFormats output_format) throws IOException
      {
        buffer = new StringBuffer ();
        indent_factor = output_format == JSONOutputFormats.PRETTY_HTML ? html_indent : STANDARD_INDENT;
        indent = -indent_factor;
        pretty_print = output_format == JSONOutputFormats.PRETTY_HTML || output_format == JSONOutputFormats.PRETTY_PRINT;
        java_script_string = output_format == JSONOutputFormats.JAVASCRIPT_STRING;
        html_mode = output_format == JSONOutputFormats.PRETTY_HTML;
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
*/
