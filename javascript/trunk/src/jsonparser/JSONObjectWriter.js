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

 org.webpki.json.JSONObjectWriter = function (/* optional argument */optional_object_or_reader)
{
    /* int */this.STANDARD_INDENT = 2;

    /* JSONObject */this.root = null;

    /* String */this.buffer = null;
    
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
        this.root = new org.webpki.json.JSONObject ();
    }
    else if (optional_object_or_reader instanceof org.webpki.json.JSONObject)
    {
        this.root = optional_object_or_reader;
    }
    else if (optional_object_or_reader instanceof org.webpki.json.JSONObjectReader)
    {
        this.root = optional_object_or_reader.root;
        if (this.root._isArray ())
        {
            org.webpki.json.JSONError._error ("You cannot update array objects");
        }
    }
    else
    {
        org.webpki.json.JSONError._error ("Wrong init of org.webpki.json.JSONObjectWriter");
    }
};
    
/* JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype._setProperty = function (/* String */name, /* JSONValue */value)
{
    this.root._setProperty (name, value);
    return this;
};

/* public void */org.webpki.json.JSONObjectWriter.prototype.setupForRewrite = function (/* String */name)
{
    for (var i = 0; i < this.root.property_list.length; i++)
    {
        if (this.root.property_list[i].name == name)
        {
            this.root.property_list[i].value = null;
            return;
        }
    }
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setString = function (/* String */name, /* String */value)
{
    if (typeof value != "string")
    {
        org.webpki.json.JSONError._error ("Bad string: " + name);
    }
    return this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.STRING, value));
};

/* String */org.webpki.json.JSONObjectWriter._intTest = function (/* int */value)
{
    var int_string = value.toString ();
    if (typeof value != "number" || int_string.indexOf ('.') >= 0)
    {
        org.webpki.json.JSONError._error ("Bad integer: " + int_string);
    }
    return int_string;
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setInt = function (/* String */name, /* int */value)
{
    return this._setProperty (name,
                              new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.INTEGER,
                                                             org.webpki.json.JSONObjectWriter._intTest (value)));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setLong = function (/* String */name, /* BigInteger */value)
{
    return this.setBigInteger (name, value.getLong ());
};

/* String */org.webpki.json.JSONObjectWriter._doubleTest = function (/* double */value)
{
    if (typeof value != "number")
    {
        org.webpki.json.JSONError._error ("Bad float type " + (typeof value));
    }
    return value.toString ();
};

/* String */org.webpki.json.JSONObjectWriter._bigDecimalTest = function (/* BigDecimal */value)
{
    if (typeof value != "string")
    {
        org.webpki.json.JSONError._error ("Bad big decimal type " + (typeof value));
    }
    if (!org.webpki.json.JSONParser.INTEGER_PATTERN.test (value) &&
        (!org.webpki.json.JSONParser.DECIMAL_INITIAL_PATTERN.test (value) || 
         org.webpki.json.JSONParser.DECIMAL_2DOUBLE_PATTERN.test (value)))
    {
        org.webpki.json.JSONError._error ("Bad big decimal syntax: " + value);
    }
    return value;
};

/* String */org.webpki.json.JSONObjectWriter._boolTest = function (/* boolean */value)
{
    if (typeof value != "boolean")
    {
        org.webpki.json.JSONError._error ("Bad bool type " + (typeof value));
    }
    return value.toString ();
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setDouble = function (/* String */name, /* double */value)
{
    return this._setProperty (name, 
                              new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.DOUBLE, 
                                                             org.webpki.json.JSONObjectWriter._doubleTest (value)));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setBigInteger = function (/* String */name, /* BigInteger */value)
{
    return this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.INTEGER, value.toString ()));
};

// No real support for BigDecimal but at least text parsing is performed

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setBigDecimal = function (/* String */name, /* BigDecimal */value)
{
    return this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.DECIMAL, org.webpki.json.JSONObjectWriter._bigDecimalTest (value)));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setBoolean = function (/* String */name, /* boolean */value)
{
    return this._setProperty (name, 
                              new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.BOOLEAN,
                                                             org.webpki.json.JSONObjectWriter._boolTest (value)));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setNULL = function (/* String */name)
{
    return this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.NULL, "null"));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setDateTime = function (/* String */name, /* Date */date_time)
{
    return this.setString (name, date_time.toISOString ());
};

/*
/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setBinary = function (/* String */name, /* Uint8Array */ value) 
{
    return this.setString (name, org.webpki.util.Base64URL.encode (value));
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setObject = function (/*String */name)
{
    /* JSONObject */ var sub_object = new org.webpki.json.JSONObject ();
    this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, sub_object));
    return new org.webpki.json.JSONObjectWriter (sub_object);
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.createContainerObject = function (/* String */name)
{
    /* JSONObjectWriter */var container = new org.webpki.json.JSONObjectWriter (new org.webpki.json.JSONObject ());
    container._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, this.root));
    return container;
};

/* public JSONArrayWriter */org.webpki.json.JSONObjectWriter.prototype.setArray = function (/* String */name)
{
    /* JSONValue[] */var array = [];
    this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, array));
    return new org.webpki.json.JSONArrayWriter (array);
};

/* JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype._setStringArray = function (/* String */name, /* String[] */values, /* JSONTypes */json_type)
{
    /* JSONValue[] */var array = [];
    for (var i = 0; i < values.length; i++)
    {
        array[i] = new org.webpki.json.JSONValue (json_type, values[i]);
    }
    return this._setProperty (name, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, array));
};

/* JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setBinaryArray = function (/* String */name, /* Uint8Array[] */values)
{
    /* String[] */var array = [];
    for (var i = 0; i < values.length; i++)
    {
        array[i] = org.webpki.util.Base64URL.encode (values[i]);
    }
    return this.setStringArray (name, array);
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setStringArray = function (/* String */name, /* String[] */values)
{
    return this._setStringArray (name, values, org.webpki.json.JSONTypes.STRING);
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
        org.webpki.json.JSONObjectWriter writer = new org.webpki.json.JSONObjectWriter ();
    
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
        byte[] json = writer.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT);
    
        // Print the signed document on the console
        System.out.println ("Signed doc:\n" + new String (json, "UTF-8"));
          
        // Parse the document
        org.webpki.json.JSONObjectReader reader = org.webpki.json.JSONParser.parse (json);
         
        // Get and verify the signature
        JSONSignatureDecoder json_signature = reader.getSignature ();
        json_signature.verify (new JSONAsymKeyVerifier (public_key));
         
        // Print the document payload on the console
        System.out.println ("Returned data: " + reader.getString ("MyProperty"));
      }
 </pre>
     */

/*

org.webpki.json.JSONObjectWriter.swriteCryptoBinary = function (BigInteger value,  String name)
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

    public org.webpki.json.JSONObjectWriter setSignature (JSONSigner signer) throws IOException
      {
        org.webpki.json.JSONObjectWriter signature_writer = setObject (JSONSignatureDecoder.SIGNATURE_JSON);
        signature_writer.setString (JSONSignatureDecoder.ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
        signer.writeKeyInfoData (signature_writer.setObject (JSONSignatureDecoder.KEY_INFO_JSON).setXMLDSigECCurveOption (xml_dsig_named_curve));
        if (signer.extensions != null)
          {
            JSONValue[] array = new JSONValue[] ();
            for (org.webpki.json.JSONObjectWriter jor : signer.extensions)
              {
                array.add (new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, jor.root));
              }
            signature_writer.setProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, array));
          }
        signature_writer.setBinary (JSONSignatureDecoder.SIGNATURE_VALUE_JSON, signer.signData (org.webpki.json.JSONObjectWriter._getCanonicalizedSubset (root)));
        return this;
      }
    
    public org.webpki.json.JSONObjectWriter setPublicKey (PublicKey public_key) throws IOException
      {
        org.webpki.json.JSONObjectWriter public_key_writer = setObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
        if (key_alg.isRSAKey ())
          {
            org.webpki.json.JSONObjectWriter rsa_key_writer = public_key_writer.setObject (JSONSignatureDecoder.RSA_JSON);
            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
            rsa_key_writer.writeCryptoBinary (rsa_public.getModulus (), JSONSignatureDecoder.MODULUS_JSON);
            rsa_key_writer.writeCryptoBinary (rsa_public.getPublicExponent (), JSONSignatureDecoder.EXPONENT_JSON);
          }
        else
          {
            org.webpki.json.JSONObjectWriter ec_key_writer = public_key_writer.setObject (JSONSignatureDecoder.EC_JSON);
            ec_key_writer.setString (JSONSignatureDecoder.NAMED_CURVE_JSON, xml_dsig_named_curve ?
               KeyAlgorithms.XML_DSIG_CURVE_PREFIX + key_alg.getECDomainOID () : key_alg.getURI ());
            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
            ec_key_writer.writeCryptoBinary (ec_point.getAffineX (), JSONSignatureDecoder.X_JSON);
            ec_key_writer.writeCryptoBinary (ec_point.getAffineY (), JSONSignatureDecoder.Y_JSON);
          }
        return this;
      }

    public org.webpki.json.JSONObjectWriter setXMLDSigECCurveOption (boolean flag)
      {
        xml_dsig_named_curve = flag;
        return this;
      }

    public org.webpki.json.JSONObjectWriter setX509CertificatePath (X509Certificate[] certificate_path) throws IOException
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
/* void */org.webpki.json.JSONObjectWriter.prototype._beginObject = function (/* boolean */array_flag)
{
    this._indentLine ();
    this._spaceOut ();
    if (array_flag)
    {
        this.indent++;
        this.buffer += '[';
    }
    this.buffer += '{';
    this._indentLine ();
};

/* void */org.webpki.json.JSONObjectWriter.prototype._newLine = function ()
{
    if (this.pretty_print)
    {
        this.buffer += this.html_mode ? "<br>" : "\n";
    }
};

/* void */org.webpki.json.JSONObjectWriter.prototype._indentLine = function ()
{
    this.indent += this.indent_factor;
};

/* void */org.webpki.json.JSONObjectWriter.prototype._undentLine = function ()
{
    this.indent -= this.indent_factor;
};

/* void */org.webpki.json.JSONObjectWriter.prototype._endObject = function ()
{
    this._newLine ();
    this._undentLine ();
    this._spaceOut ();
    this._undentLine ();
    this.buffer += '}';
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printOneElement = function (/* JSONValue */json_value)
{
    switch (json_value.type)
    {
        case org.webpki.json.JSONTypes.ARRAY:
            this._printArray (/* JSONValue[] */json_value.value, false);
            break;
    
        case org.webpki.json.JSONTypes.OBJECT:
            this._newLine ();
            this._printObject (/* JSONObject */json_value.value, false);
            break;
    
        default:
            this._printSimpleValue (json_value, false);
    }
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printObject = function (/* JSONObject */object, /* boolean */array_flag)
{
    this._beginObject (array_flag);
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
        this._newLine ();
        next = true;
        this._printProperty (property);
        this._printOneElement (json_value);
    }
    this._endObject ();
};
  
/* boolean */org.webpki.json.JSONObjectWriter.prototype._complex = function (/* JSONTypes */json_type)
{
    return json_type.enumvalue >= 10;
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printArray = function (/* JSONValue[] */array, /* boolean */array_flag)
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
            if (this._complex (first_type) != this._complex (json_value.type) ||
                    (this._complex (first_type) && first_type != json_value.type))

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
                this._printOneElement (json_value);
            }
        }
        else if (first_type == org.webpki.json.JSONTypes.OBJECT)
        {
            this._printArrayObjects (array);
        }
        else if (first_type == org.webpki.json.JSONTypes.ARRAY)
        {
            this._newLine ();
            this._indentLine ();
            this._spaceOut ();
            this.buffer += '[';
            /* boolean */var next = false;
            for (var i = 0; i < array.length; i++)
            {
                var json_value = array[i];
                /* JSONValue[] */var sub_array = json_value.value;
                /* boolean */var extra_pretty = sub_array.length == 0 || !this._complex (sub_array[0].type);
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
                    this._newLine ();
                    this._indentLine ();
                    this._spaceOut ();
                }
                this._printArray (sub_array, true);
                if (extra_pretty)
                {
                    this._undentLine ();
                }
            }
            this._newLine ();
            this._spaceOut ();
            this._undentLine ();
        }
        else
        {
            this._printArraySimple (array, array_flag);
        }
    }
    this.buffer += ']';
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printArraySimple = function (/* JSONValue[] */array, /* boolean */array_flag)
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
        this._indentLine ();
        this._newLine ();
        this._spaceOut ();
    }
    this.buffer += '[';
    if (broken_lines)
    {
        this._indentLine ();
        this._newLine ();
    }
    for (var i = 0; i < array.length; i++)
    {
        if (next)
        {
            this.buffer += ',';
            if (broken_lines)
            {
                this._newLine ();
            }
        }
        if (broken_lines)
        {
            this._spaceOut ();
        }
        this._printSimpleValue (array[i], false);
        next = true;
    }
    if (broken_lines)
    {
        this._undentLine ();
        this._newLine ();
        this._spaceOut ();
        if (!array_flag)
        {
            this._undentLine ();
        }
    }
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printArrayObjects = function (/* JSONValue[] */array)
{
    /* boolean */var next = false;
    for (var i = 0; i < array.length; i++)
    {
        if (next)
        {
            this.buffer += ',';
        }
        this._newLine ();
        this._printObject (array[i].value, !next);
        next = true;
    }
    this.indent--;
};

/* void */org.webpki.json.JSONObjectWriter.prototype._printSimpleValue = function (/* JSONValue */value, /* boolean */property)
{
    /* String */var string = value.value;
    if (value.type != org.webpki.json.JSONTypes.STRING)
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
                this._escapeCharacter (c);
                break;
    
            case '\b':
                this._escapeCharacter ('b');
                break;
    
            case '\f':
                this._escapeCharacter ('f');
                break;
    
            case '\n':
                this._escapeCharacter ('n');
                break;
    
            case '\r':
                this._escapeCharacter ('r');
                break;
    
            case '\t':
                this._escapeCharacter ('t');
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
                    this._escapeCharacter ('u');
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

/* void */org.webpki.json.JSONObjectWriter.prototype._escapeCharacter = function (/* char */c)
{
    if (this.java_script_string)
    {
        this.buffer += '\\';
    }
    this.buffer += '\\' + c;
};

/* void */org.webpki.json.JSONObjectWriter.prototype._singleSpace = function ()
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

/* void */org.webpki.json.JSONObjectWriter.prototype._printProperty = function (/* String */name)
{
    this._spaceOut ();
    this._printSimpleValue (new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.STRING, name), true);
    this.buffer += ':';
    this._singleSpace ();
};

/* void */org.webpki.json.JSONObjectWriter.prototype._spaceOut = function ()
{
    for (var i = 0; i < this.indent; i++)
    {
        this._singleSpace ();
    }
};

/* String */org.webpki.json.JSONObjectWriter._getCanonicalizedSubset = function (/*JSONObject */signature_object_in)
{
    /* JSONObjectWriter */var writer = new org.webpki.json.JSONObjectWriter (signature_object_in);
    /* String*/var result = writer.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED);
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

/* String */org.webpki.json.JSONObjectWriter.prototype.serializeJSONObject = function (/* JSONOutputFormats */output_format)
{
    this.buffer = new String ();
    this.indent_factor = output_format == org.webpki.json.JSONOutputFormats.PRETTY_HTML ? this.html_indent : this.STANDARD_INDENT;
    this.indent = -this.indent_factor;
    this.pretty_print = output_format == org.webpki.json.JSONOutputFormats.PRETTY_HTML || output_format == org.webpki.json.JSONOutputFormats.PRETTY_PRINT;
    this.java_script_string = output_format == org.webpki.json.JSONOutputFormats.JAVASCRIPT_STRING;
    this.html_mode = output_format == org.webpki.json.JSONOutputFormats.PRETTY_HTML;
    if (this.java_script_string)
    {
        this.buffer += '\'';
    }
    if (this.root._isArray ())
    {
        this._printArray (/* JSONValue[] */this.root.property_list[0].value, false);
    }
    else
    {
        this._printObject (this.root, false);
    }
    if (output_format == org.webpki.json.JSONOutputFormats.PRETTY_PRINT)
    {
        this._newLine ();
    }
    else if (this.java_script_string)
    {
        this.buffer += '\'';
    }
    return this.buffer;
};
/*
    public static byte[] serializeParsedJSONDocument (JSONDecoder document, org.webpki.json.JSONOutputFormats output_format) throws IOException
      {
        return new org.webpki.json.JSONObjectWriter (document.root).serializeJSONObject (output_format);
      }
  
    public static void setCanonicalizationDebugFile (String file) throws IOException
      {
        ArrayUtil.writeFile (file, "Canonicalization Debug Output".getBytes ("UTF-8"));
        canonicalization_debug_file = file;
      }

    public static byte[] parseAndFormat (byte[] json_utf8, org.webpki.json.JSONOutputFormats output_format) throws IOException
      {
        return new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse (json_utf8)).serializeJSONObject (output_format);
      }

*/
