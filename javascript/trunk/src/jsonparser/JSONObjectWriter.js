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
        if (this.root._isArray ())
        {
            JSONObject._error ("You cannot update array objects");
        }
    }
    else
    {
        JSONObject._error ("Wrong init of JSONObjectWriter");
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

/* public JSONObjectWriter */JSONObjectWriter.prototype.setString = function (/* String */name, /* String */value)
{
    if (typeof value != "string")
    {
        JSONObject._error ("Bad string: " + name);
    }
    return this._addProperty (name, new JSONValue (JSONTypes.STRING, value));
};

/* public JSONObjectWriter */JSONObjectWriter.prototype.setInt = function (/* String */name, /* int */value)
{
    var int_string = value.toString ();
    if (typeof value != "number" || int_string.indexOf ('.') >= 0)
    {
        JSONObject._error ("Bad integer: " + name);
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
*/

/* public JSONObjectWriter */JSONObjectWriter.prototype.setBoolean = function (/* String */name, /* boolean */value)
{
    return this._addProperty (name, new JSONValue (JSONTypes.BOOLEAN, value.toString ()));
};

/*
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

/* JSONObjectWriter */JSONObjectWriter.prototype._setStringArray = function (/* String */name, /* String[] */values, /* JSONTypes */json_type)
{
    /* Vector<JSONValue> */var array = [] /* new Vector<JSONValue> () */;
    for (var i = 0; i < values.length; i++)
    {
        array[i] = new JSONValue (json_type, values[i]);
    }
    return this._addProperty (name, new JSONValue (JSONTypes.ARRAY, array));
};

/*

JSONObjectWriter.prototype.setBinaryArray (String name, Vector<byte[]> values) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (byte[] value : values)
          {
            array.add (Base64URL.getBase64URLFromBinary (value));
          }
        return setStringArray (name, array.toArray (new String[0]));
      }
*/

/* public JSONObjectWriter */JSONObjectWriter.prototype.setStringArray = function (/* String */name, /* String[] */values)
{
    return this._setStringArray (name, values, JSONTypes.STRING);
};


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
*/
/* void */JSONObjectWriter.prototype.beginObject = function (/* boolean */array_flag)
{
    this.indentLine ();
    this.spaceOut ();
    if (array_flag)
    {
        this.indent++;
        this.buffer += '[';
    }
    this.buffer += '{';
    this.indentLine ();
};

/* void */JSONObjectWriter.prototype.newLine = function ()
{
    if (this.pretty_print)
    {
        this.buffer += this.html_mode ? "<br>" : "\n";
    }
};

/* void */JSONObjectWriter.prototype.indentLine = function ()
{
    this.indent += this.indent_factor;
};

/* void */JSONObjectWriter.prototype.undentLine = function ()
{
    this.indent -= this.indent_factor;
};

/* void */JSONObjectWriter.prototype.endObject = function ()
{
    this.newLine ();
    this.undentLine ();
    this.spaceOut ();
    this.undentLine ();
    this.buffer += '}';
};

/* void */JSONObjectWriter.prototype.printOneElement = function (/* JSONValue */json_value)
{
    switch (json_value.type)
    {
        case JSONTypes.ARRAY:
            this.printArray (/* (Vector<JSONValue>) */json_value.value, false);
            break;
    
        case JSONTypes.OBJECT:
            this.newLine ();
            this.printObject (/*(JSONObject) */json_value.value, false);
            break;
    
        default:
            this.printSimpleValue (json_value, false);
    }
};

/* void */JSONObjectWriter.prototype.printObject = function (/* JSONObject */object, /* boolean */array_flag)
{
    this.beginObject (array_flag);
    /* boolean */var next = false;
    var length = object.property_list.length;
    for (var i = 0; i < length; i++)
    {
        /* JSONValue */var json_value = object.property_list[i].value;
        /* String */var property = object.property_list[i].name;
        if (next)
        {
            this.buffer += ',';
        }
        this.newLine ();
        next = true;
        this.printProperty (property);
        this.printOneElement (json_value);
    }
    this.endObject ();
};
  
/* boolean */JSONObjectWriter.prototype.complex = function (/* JSONTypes */json_type)
{
    return json_type.enumvalue >= 10;
};

/* void */JSONObjectWriter.prototype.printArray = function (/* Vector<JSONValue> */array, /* boolean */array_flag)
{
    if (array.length == 0)
    {
        this.buffer += '[';
    }
    else
    {
        /* boolean */var mixed = false;
        /* JSONTypes */var first_type = array[0].type;
        for (var i = 0; i < array.length; i++)
        {
            var json_value = array[i];
            if (this.complex (first_type) != this.complex (json_value.type) ||
                    (this.complex (first_type) && first_type != json_value.type))

            {
                mixed = true;
                break;
            }
        }
        if (mixed)
        {
            this.buffer += '[';
            /* boolean */var next = false;
            for (var i = 0; i < array.length; i++)
            {
                var json_value = array[i];
                if (next)
                {
                    this.buffer += ',';
                }
                else
                {
                    next = true;
                }
                this.printOneElement (json_value);
            }
        }
        else if (first_type == JSONTypes.OBJECT)
        {
            this.printArrayObjects (array);
        }
        else if (first_type == JSONTypes.ARRAY)
        {
            this.newLine ();
            this.indentLine ();
            this.spaceOut ();
            this.buffer += '[';
            /* boolean */var next = false;
            for (var i = 0; i < array.length; i++)
            {
                var json_value = array[i];
                /* Vector<JSONValue> */var sub_array = /* (Vector<JSONValue>) */json_value.value;
                /* boolean */var extra_pretty = sub_array.length == 0 || !complex (sub_array[0].type);
                if (next)
                {
                    this.buffer += ',';
                }
                else
                {
                    next = true;
                }
                if (extra_pretty)
                {
                    this.newLine ();
                    this.indentLine ();
                    this.spaceOut ();
                }
                this.printArray (sub_array, true);
                if (extra_pretty)
                {
                    this.undentLine ();
                }
            }
            this.newLine ();
            this.spaceOut ();
            this.undentLine ();
        }
        else
        {
            this.printArraySimple (array, array_flag);
        }
    }
    this.buffer += ']';
};

/* void */JSONObjectWriter.prototype.printArraySimple = function (/* Vector<JSONValue> */array, /* boolean */array_flag)
{
    /* int */var length = 0;
    for (var i = 0; i < array.length; i++)
    {
        length += array[i].value.length;
    }
    /* boolean */var broken_lines = length > 100;
    /* boolean */var next = false;
    if (broken_lines && !array_flag)
    {
        this.indentLine ();
        this.newLine ();
        this.spaceOut ();
    }
    this.buffer += '[';
    if (broken_lines)
    {
        this.indentLine ();
        this.newLine ();
    }
    for (var i = 0; i < array.length; i++)
    {
        if (next)
        {
            this.buffer += ',';
            if (broken_lines)
            {
                this.newLine ();
            }
        }
        if (broken_lines)
        {
            this.spaceOut ();
        }
        this.printSimpleValue (array[i], false);
        next = true;
    }
    if (broken_lines)
    {
        this.undentLine ();
        this.newLine ();
        this.spaceOut ();
        if (!array_flag)
        {
            this.undentLine ();
        }
    }
};

/* void */JSONObjectWriter.prototype.printArrayObjects = function (/* Vector<JSONValue> */array)
{
    /* boolean */var next = false;
    for (var i = 0; i < array.length; i++)
    {
        if (next)
        {
            this.buffer += ',';
        }
        this.newLine ();
        this.printObject (array[i].value, !next);
        next = true;
    }
    this.indent--;
};

/* void */JSONObjectWriter.prototype.printSimpleValue = function (/* JSONValue */value, /* boolean */property)
{
    /* String */var string = /* (String) */value.value;
    if (value.type != JSONTypes.STRING)
    {
        if (this.html_mode)
        {
            this.buffer += "<span style=\"color:" + html_variable_color + "\">";
        }
        this.buffer += string;
        if (this.html_mode)
        {
            this.buffer += "</span>";
        }
        return;
    }
    if (this.html_mode)
    {
        this.buffer += "&quot;<span style=\"color:" +
                            (property ?
                                    (string.indexOf ('@') == 0) ?
                                        this.html_keyword_color : this.html_property_color
                                      : this.html_string_color) +
                        "\">";
    }
    else
    {
        this.buffer += '"';
    }
    for (var i = 0; i < string.length; i++)
    {
        var c = string.charAt (i);
        if (this.html_mode)
        {
            switch (c)
            {
                //
                //      HTML needs specific escapes...
                //
                case '<':
                    this.buffer += "&lt;";
                    continue;
    
                case '>':
                    this.buffer += "&gt;";
                    continue;
    
                case '&':
                    this.buffer += "&amp;";
                    continue;
    
                case '"':
                    this.buffer += "\\&quot;";
                    continue;
            }
        }

        switch (c)
        {
            case '\\':
                if (this.java_script_string)
                {
                    // JS escaping need \\\\ in order to produce a JSON \\
                    this.buffer += '\\';
                }
    
            case '"':
                this.escapeCharacter (c);
                break;
    
            case '\b':
                this.escapeCharacter ('b');
                break;
    
            case '\f':
                this.escapeCharacter ('f');
                break;
    
            case '\n':
                this.escapeCharacter ('n');
                break;
    
            case '\r':
                this.escapeCharacter ('r');
                break;
    
            case '\t':
                this.escapeCharacter ('t');
                break;
    
            case '\'':
                if (this.java_script_string)
                {
                    // Since we assumed that the JSON object was enclosed between '' we need to escape ' as well
                    this.buffer += '\\';
                }
    
            default:
                var utf_value = c.charCodeAt (0);
                if (utf_value < 0x20)
                {
                    this.escapeCharacter ('u');
                    for (var j = 0; j < 4; j++)
                    {
                        /*int */var hex = utf_value >>> 12;
                        this.buffer += String.fromCharCode (hex > 9 ? hex + 87 : hex + 48);
                        utf_value <<= 4;
                    }
                    break;
                }
                this.buffer += c;
        }
    }
    if (this.html_mode)
    {
        this.buffer += "</span>&quot;";
    }
    else
    {
        this.buffer += '"';
    }
};

/* void */JSONObjectWriter.prototype.escapeCharacter = function (/* char */c)
{
    if (this.java_script_string)
    {
        this.buffer += '\\';
    }
    this.buffer += '\\' + c;
};

/* void */JSONObjectWriter.prototype.singleSpace = function ()
{
    if (this.pretty_print)
    {
        if (this.html_mode)
        {
            this.buffer += "&nbsp;";
        }
        else
        {
            this.buffer += ' ';
        }
    }
};

/* void */JSONObjectWriter.prototype.printProperty = function (/* String */name)
{
    this.spaceOut ();
    this.printSimpleValue (new JSONValue (JSONTypes.STRING, name), true);
    this.buffer += ':';
    this.singleSpace ();
};

/* void */JSONObjectWriter.prototype.spaceOut = function ()
{
    for (var i = 0; i < this.indent; i++)
    {
        this.singleSpace ();
    }
};

/* String */JSONObjectWriter.getCanonicalizedSubset = function (/*JSONObject */signature_object_in)
{
    /* JSONObjectWriter */var writer = new JSONObjectWriter (signature_object_in);
    /* String*/var result = writer.serializeJSONObject (JSONOutputFormats.CANONICALIZED);
    /*
        if (canonicalization_debug_file != null)
          {
            byte[] other = ArrayUtil.readFile (canonicalization_debug_file);
            ArrayUtil.writeFile (canonicalization_debug_file,
                                 ArrayUtil.add (other, 
                                                new StringBuffer ("\n\n").append (writer.buffer).toString ().getBytes ("UTF-8")));
          }
     */
    return result;
};

/* String */JSONObjectWriter.prototype.serializeJSONObject = function (/* JSONOutputFormats */output_format)
{
    this.buffer = new String ();
    this.indent_factor = output_format == JSONOutputFormats.PRETTY_HTML ? this.html_indent : this.STANDARD_INDENT;
    this.indent = -this.indent_factor;
    this.pretty_print = output_format == JSONOutputFormats.PRETTY_HTML || output_format == JSONOutputFormats.PRETTY_PRINT;
    this.java_script_string = output_format == JSONOutputFormats.JAVASCRIPT_STRING;
    this.html_mode = output_format == JSONOutputFormats.PRETTY_HTML;
    if (this.java_script_string)
    {
        this.buffer += '\'';
    }
    if (this.root._isArray ())
    {
        this.printArray (/* (Vector<JSONValue>) */this.root.property_list[0].value, false);
    }
    else
    {
        this.printObject (this.root, false);
    }
    if (output_format == JSONOutputFormats.PRETTY_PRINT)
    {
        this.newLine ();
    }
    else if (this.java_script_string)
    {
        this.buffer += '\'';
    }
    return this.buffer;
};
/*
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

*/
