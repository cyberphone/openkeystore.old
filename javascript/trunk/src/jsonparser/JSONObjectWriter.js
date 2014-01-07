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

 webpki.org.json.JSONObjectWriter = function (/* optional argument */optional_object_or_reader)
{
    /* int */this.STANDARD_INDENT = 2;

    /* webpki.org.json.JSONObject */this.root = null;

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
        this.root = new webpki.org.json.JSONObject ();
    }
    else if (optional_object_or_reader instanceof webpki.org.json.JSONObject)
    {
        this.root = optional_object_or_reader;
    }
    else if (optional_object_or_reader instanceof webpki.org.json.JSONObjectReader)
    {
        this.root = optional_object_or_reader.json;
        if (this.root._isArray ())
        {
            webpki.org.json.JSONError._error ("You cannot update array objects");
        }
    }
    else
    {
        webpki.org.json.JSONError._error ("Wrong init of webpki.org.json.JSONObjectWriter");
    }
};
    
/* webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype._addProperty = function (/* String */name, /* webpki.org.json.JSONValue */value)
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

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype.setString = function (/* String */name, /* String */value)
{
    if (typeof value != "string")
    {
        webpki.org.json.JSONError._error ("Bad string: " + name);
    }
    return this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.STRING, value));
};

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype.setInt = function (/* String */name, /* int */value)
{
    var int_string = value.toString ();
    if (typeof value != "number" || int_string.indexOf ('.') >= 0)
    {
        webpki.org.json.JSONError._error ("Bad integer: " + name);
    }
    return this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.INTEGER, int_string));
};

/*
    public webpki.org.json.JSONObjectWriter setLong (String name, long value) throws IOException
      {
        return addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.INTEGER, Long.toString (value)));
      }

    public webpki.org.json.JSONObjectWriter setDouble (String name, double value) throws IOException
      {
        return addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.DOUBLE, Double.toString (value)));
      }

    public webpki.org.json.JSONObjectWriter setBigInteger (String name, BigInteger value) throws IOException
      {
        return addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.INTEGER, value.toString ()));
      }

    public webpki.org.json.JSONObjectWriter setBigDecimal (String name, BigDecimal value) throws IOException
      {
        return addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.DECIMAL, value.toString ()));
      }
*/

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype.setBoolean = function (/* String */name, /* boolean */value)
{
    return this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.BOOLEAN, value.toString ()));
};

/*
    public webpki.org.json.JSONObjectWriter setNULL (String name) throws IOException
      {
        return addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.NULL, "null"));
      }

    public webpki.org.json.JSONObjectWriter setDateTime (String name, Date date_time) throws IOException
      {
        return setString (name, ISODateTime.formatDateTime (date_time));
      }

    public webpki.org.json.JSONObjectWriter setBinary (String name, byte[] value) throws IOException 
      {
        return setString (name, Base64URL.getBase64URLFromBinary (value));
      }
*/

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype.setObject = function (/*String */name)
{
    /* webpki.org.json.JSONObject */ var sub_object = new webpki.org.json.JSONObject ();
    this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.OBJECT, sub_object));
    return new webpki.org.json.JSONObjectWriter (sub_object);
};

/*
    public webpki.org.json.JSONObjectWriter createContainerObject (String name) throws IOException
      {
        webpki.org.json.JSONObjectWriter container = new webpki.org.json.JSONObjectWriter (new webpki.org.json.JSONObject ());
        container.addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.OBJECT, this.root));
        return container;
      }
*/

/* public webpki.org.json.JSONArrayWriter */webpki.org.json.JSONObjectWriter.prototype.setArray = function (/* String */name)
{
    /* Vector<webpki.org.json.JSONValue> */var array = [] /* new Vector<webpki.org.json.JSONValue> ()*/;
    this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.ARRAY, array));
    return new webpki.org.json.JSONArrayWriter (array);
};

/* webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype._setStringArray = function (/* String */name, /* String[] */values, /* webpki.org.json.JSONTypes */json_type)
{
    /* Vector<webpki.org.json.JSONValue> */var array = [] /* new Vector<webpki.org.json.JSONValue> () */;
    for (var i = 0; i < values.length; i++)
    {
        array[i] = new webpki.org.json.JSONValue (json_type, values[i]);
    }
    return this._addProperty (name, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.ARRAY, array));
};

/*

webpki.org.json.JSONObjectWriter.prototype.setBinaryArray (String name, Vector<byte[]> values) throws IOException
      {
        Vector<String> array = new Vector<String> ();
        for (byte[] value : values)
          {
            array.add (Base64URL.getBase64URLFromBinary (value));
          }
        return setStringArray (name, array.toArray (new String[0]));
      }
*/

/* public webpki.org.json.JSONObjectWriter */webpki.org.json.JSONObjectWriter.prototype.setStringArray = function (/* String */name, /* String[] */values)
{
    return this._setStringArray (name, values, webpki.org.json.JSONTypes.STRING);
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
        webpki.org.json.JSONObjectWriter writer = new webpki.org.json.JSONObjectWriter ();
    
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
        byte[] json = writer.serializeJSONObject (webpki.org.json.JSONOutputFormats.PRETTY_PRINT);
    
        // Print the signed document on the console
        System.out.println ("Signed doc:\n" + new String (json, "UTF-8"));
          
        // Parse the document
        webpki.org.json.JSONObjectReader reader = webpki.org.json.JSONParser.parse (json);
         
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

    public webpki.org.json.JSONObjectWriter setSignature (JSONSigner signer) throws IOException
      {
        webpki.org.json.JSONObjectWriter signature_writer = setObject (JSONSignatureDecoder.SIGNATURE_JSON);
        signature_writer.setString (JSONSignatureDecoder.ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
        signer.writeKeyInfoData (signature_writer.setObject (JSONSignatureDecoder.KEY_INFO_JSON).setXMLDSigECCurveOption (xml_dsig_named_curve));
        if (signer.extensions != null)
          {
            Vector<webpki.org.json.JSONValue> array = new Vector<webpki.org.json.JSONValue> ();
            for (webpki.org.json.JSONObjectWriter jor : signer.extensions)
              {
                array.add (new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.OBJECT, jor.root));
              }
            signature_writer.addProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.ARRAY, array));
          }
        signature_writer.setBinary (JSONSignatureDecoder.SIGNATURE_VALUE_JSON, signer.signData (webpki.org.json.JSONObjectWriter.getCanonicalizedSubset (root)));
        return this;
      }
    
    public webpki.org.json.JSONObjectWriter setPublicKey (PublicKey public_key) throws IOException
      {
        webpki.org.json.JSONObjectWriter public_key_writer = setObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
        if (key_alg.isRSAKey ())
          {
            webpki.org.json.JSONObjectWriter rsa_key_writer = public_key_writer.setObject (JSONSignatureDecoder.RSA_JSON);
            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
            rsa_key_writer.writeCryptoBinary (rsa_public.getModulus (), JSONSignatureDecoder.MODULUS_JSON);
            rsa_key_writer.writeCryptoBinary (rsa_public.getPublicExponent (), JSONSignatureDecoder.EXPONENT_JSON);
          }
        else
          {
            webpki.org.json.JSONObjectWriter ec_key_writer = public_key_writer.setObject (JSONSignatureDecoder.EC_JSON);
            ec_key_writer.setString (JSONSignatureDecoder.NAMED_CURVE_JSON, xml_dsig_named_curve ?
               KeyAlgorithms.XML_DSIG_CURVE_PREFIX + key_alg.getECDomainOID () : key_alg.getURI ());
            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
            ec_key_writer.writeCryptoBinary (ec_point.getAffineX (), JSONSignatureDecoder.X_JSON);
            ec_key_writer.writeCryptoBinary (ec_point.getAffineY (), JSONSignatureDecoder.Y_JSON);
          }
        return this;
      }

    public webpki.org.json.JSONObjectWriter setXMLDSigECCurveOption (boolean flag)
      {
        xml_dsig_named_curve = flag;
        return this;
      }

    public webpki.org.json.JSONObjectWriter setX509CertificatePath (X509Certificate[] certificate_path) throws IOException
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
/* void */webpki.org.json.JSONObjectWriter.prototype.beginObject = function (/* boolean */array_flag)
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

/* void */webpki.org.json.JSONObjectWriter.prototype.newLine = function ()
{
    if (this.pretty_print)
    {
        this.buffer += this.html_mode ? "<br>" : "\n";
    }
};

/* void */webpki.org.json.JSONObjectWriter.prototype.indentLine = function ()
{
    this.indent += this.indent_factor;
};

/* void */webpki.org.json.JSONObjectWriter.prototype.undentLine = function ()
{
    this.indent -= this.indent_factor;
};

/* void */webpki.org.json.JSONObjectWriter.prototype.endObject = function ()
{
    this.newLine ();
    this.undentLine ();
    this.spaceOut ();
    this.undentLine ();
    this.buffer += '}';
};

/* void */webpki.org.json.JSONObjectWriter.prototype.printOneElement = function (/* webpki.org.json.JSONValue */json_value)
{
    switch (json_value.type)
    {
        case webpki.org.json.JSONTypes.ARRAY:
            this.printArray (/* (Vector<webpki.org.json.JSONValue>) */json_value.value, false);
            break;
    
        case webpki.org.json.JSONTypes.OBJECT:
            this.newLine ();
            this.printObject (/*(webpki.org.json.JSONObject) */json_value.value, false);
            break;
    
        default:
            this.printSimpleValue (json_value, false);
    }
};

/* void */webpki.org.json.JSONObjectWriter.prototype.printObject = function (/* webpki.org.json.JSONObject */object, /* boolean */array_flag)
{
    this.beginObject (array_flag);
    /* boolean */var next = false;
    var length = object.property_list.length;
    for (var i = 0; i < length; i++)
    {
        /* webpki.org.json.JSONValue */var json_value = object.property_list[i].value;
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
  
/* boolean */webpki.org.json.JSONObjectWriter.prototype.complex = function (/* webpki.org.json.JSONTypes */json_type)
{
    return json_type.enumvalue >= 10;
};

/* void */webpki.org.json.JSONObjectWriter.prototype.printArray = function (/* Vector<webpki.org.json.JSONValue> */array, /* boolean */array_flag)
{
    if (array.length == 0)
    {
        this.buffer += '[';
    }
    else
    {
        /* boolean */var mixed = false;
        /* webpki.org.json.JSONTypes */var first_type = array[0].type;
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
        else if (first_type == webpki.org.json.JSONTypes.OBJECT)
        {
            this.printArrayObjects (array);
        }
        else if (first_type == webpki.org.json.JSONTypes.ARRAY)
        {
            this.newLine ();
            this.indentLine ();
            this.spaceOut ();
            this.buffer += '[';
            /* boolean */var next = false;
            for (var i = 0; i < array.length; i++)
            {
                var json_value = array[i];
                /* Vector<webpki.org.json.JSONValue> */var sub_array = /* (Vector<webpki.org.json.JSONValue>) */json_value.value;
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

/* void */webpki.org.json.JSONObjectWriter.prototype.printArraySimple = function (/* Vector<webpki.org.json.JSONValue> */array, /* boolean */array_flag)
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

/* void */webpki.org.json.JSONObjectWriter.prototype.printArrayObjects = function (/* Vector<webpki.org.json.JSONValue> */array)
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

/* void */webpki.org.json.JSONObjectWriter.prototype.printSimpleValue = function (/* webpki.org.json.JSONValue */value, /* boolean */property)
{
    /* String */var string = /* (String) */value.value;
    if (value.type != webpki.org.json.JSONTypes.STRING)
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

/* void */webpki.org.json.JSONObjectWriter.prototype.escapeCharacter = function (/* char */c)
{
    if (this.java_script_string)
    {
        this.buffer += '\\';
    }
    this.buffer += '\\' + c;
};

/* void */webpki.org.json.JSONObjectWriter.prototype.singleSpace = function ()
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

/* void */webpki.org.json.JSONObjectWriter.prototype.printProperty = function (/* String */name)
{
    this.spaceOut ();
    this.printSimpleValue (new webpki.org.json.JSONValue (webpki.org.json.JSONTypes.STRING, name), true);
    this.buffer += ':';
    this.singleSpace ();
};

/* void */webpki.org.json.JSONObjectWriter.prototype.spaceOut = function ()
{
    for (var i = 0; i < this.indent; i++)
    {
        this.singleSpace ();
    }
};

/* String */webpki.org.json.JSONObjectWriter.getCanonicalizedSubset = function (/*webpki.org.json.JSONObject */signature_object_in)
{
    /* webpki.org.json.JSONObjectWriter */var writer = new webpki.org.json.JSONObjectWriter (signature_object_in);
    /* String*/var result = writer.serializeJSONObject (webpki.org.json.JSONOutputFormats.CANONICALIZED);
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

/* String */webpki.org.json.JSONObjectWriter.prototype.serializeJSONObject = function (/* webpki.org.json.JSONOutputFormats */output_format)
{
    this.buffer = new String ();
    this.indent_factor = output_format == webpki.org.json.JSONOutputFormats.PRETTY_HTML ? this.html_indent : this.STANDARD_INDENT;
    this.indent = -this.indent_factor;
    this.pretty_print = output_format == webpki.org.json.JSONOutputFormats.PRETTY_HTML || output_format == webpki.org.json.JSONOutputFormats.PRETTY_PRINT;
    this.java_script_string = output_format == webpki.org.json.JSONOutputFormats.JAVASCRIPT_STRING;
    this.html_mode = output_format == webpki.org.json.JSONOutputFormats.PRETTY_HTML;
    if (this.java_script_string)
    {
        this.buffer += '\'';
    }
    if (this.root._isArray ())
    {
        this.printArray (/* (Vector<webpki.org.json.JSONValue>) */this.root.property_list[0].value, false);
    }
    else
    {
        this.printObject (this.root, false);
    }
    if (output_format == webpki.org.json.JSONOutputFormats.PRETTY_PRINT)
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
    public static byte[] serializeParsedJSONDocument (JSONDecoder document, webpki.org.json.JSONOutputFormats output_format) throws IOException
      {
        return new webpki.org.json.JSONObjectWriter (document.root).serializeJSONObject (output_format);
      }
  
    public static void setCanonicalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Canonicalization Debug Output".getBytes ("UTF-8"));
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndFormat (byte[] json_utf8, webpki.org.json.JSONOutputFormats output_format) throws IOException
      {
        return new webpki.org.json.JSONObjectWriter (webpki.org.json.JSONParser.parse (json_utf8)).serializeJSONObject (output_format);
      }

*/
