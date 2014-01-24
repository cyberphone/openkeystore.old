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

////////////////////////////////////////////////////////////////////////////////////////////
// This file contains a JSON parser supporting JCS (JSON Cleartext Signature):            //
// https://openkeystore.googlecode.com/svn/resources/trunk/docs/jcs.html                  //
//                                                                                        //
// The parser is essentially a JavaScript copy of a Java-based version available at:      //
// https://code.google.com/p/openkeystore/source/browse/library/trunk/src/org/webpki/json //
//                                                                                        //
// Note: The cryptographic operations are supposed to be performed by WebCrypto when      //
// used in a browser application.                                                         //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////


/*================================================================*/
/*             Namespace for the JSON core library                */
/*================================================================*/

"use strict";

var org = org || {};
org.webpki = org.webpki || {};
org.webpki.json = org.webpki.json || {};

/*================================================================*/
/*                        JSONArrayReader                         */
/*================================================================*/

org.webpki.json.JSONArrayReader = function (/* JSONValue[] */array)
{
    this.index = 0;
    this.array = array;
};

/* public boolean */org.webpki.json.JSONArrayReader.prototype.hasMore = function ()
{
    return this.index < this.array.length;
};

/* void */org.webpki.json.JSONArrayReader.prototype._inRangeCheck = function ()
{
    if (!this.hasMore ())
    {
        org.webpki.json.JSONError._error ("Trying to read past of array limit: " + this.index);
    }
};

/* Object */org.webpki.json.JSONArrayReader.prototype._get = function (/* JSONTypes */expected_type)
{
    this._inRangeCheck ();
    /* JSONValue */var value = this.array[this.index++];
    if (!expected_type.isCompatible (value.type))
    {
        org.webpki.json.JSONError._error ("Incompatible request: " +
                "Read=" + org.webpki.json.JSONTypes.getJSONTypeName (value.type) +
                ", Expected=" + org.webpki.json.JSONTypes.getJSONTypeName (expected_type));
    }
    return value.value;
};

/* public String */org.webpki.json.JSONArrayReader.prototype.getString = function ()
{
    return /* String */this._get (org.webpki.json.JSONTypes.STRING);
};

/* public int */org.webpki.json.JSONArrayReader.prototype.getInt = function ()
{
    return parseInt (/* String */this._get (org.webpki.json.JSONTypes.INTEGER));
};

/* BigInteger */org.webpki.json.JSONArrayReader.prototype.getLong = function ()
{
    return this.getBigInteger ().getLong ();
};

/* public BigInteger */org.webpki.json.JSONArrayReader.prototype.getBigInteger = function ()
{
    return org.webpki.math.BigInteger.fromString (this._get (org.webpki.json.JSONTypes.INTEGER));
};

//No real support for BigDecimal but at least text parsing is performed

/* public BigDecimal */org.webpki.json.JSONArrayReader.prototype.getBigDecimal = function ()
{
    return this._get (org.webpki.json.JSONTypes.DECIMAL);
};

/* public Date */org.webpki.json.JSONArrayReader.prototype.getDateTime = function ()
{
    return new Date (this.getString ());
};

/* public double */org.webpki.json.JSONArrayReader.prototype.getDouble = function ()
{
    return parseFloat (this._get (org.webpki.json.JSONTypes.DOUBLE));
};

 /* public boolean */org.webpki.json.JSONArrayReader.prototype.getBoolean = function ()
{
    return this._get (org.webpki.json.JSONTypes.BOOLEAN) == "true";
};

 /* public boolean */org.webpki.json.JSONArrayReader.prototype.getIfNULL = function ()
{
    if (this.getElementType () == org.webpki.json.JSONTypes.NULL)
    {
        this.scanAway ();
        return true;
    }
    return false;
};
 
/* public JSONArrayReader */org.webpki.json.JSONArrayReader.prototype.getArray = function ()
{
    return new org.webpki.json.JSONArrayReader (/* JSONValue[] */this._get (org.webpki.json.JSONTypes.ARRAY));
};

/* public JSONTypes */org.webpki.json.JSONArrayReader.prototype.getElementType = function ()
{
    this._inRangeCheck ();
    return this.array[this.index].type;
};

/* public JSONObjectReader */org.webpki.json.JSONArrayReader.prototype.getObject = function ()
{
    return new org.webpki.json.JSONObjectReader (/* JSONObject */this._get (org.webpki.json.JSONTypes.OBJECT));
};

/* public void */org.webpki.json.JSONArrayReader.prototype.scanAway = function ()
{
    this._get (this.getElementType ());
};

/*================================================================*/
/*                         JSONArrayWriter                        */
/*================================================================*/

org.webpki.json.JSONArrayWriter = function (optional_array)
{
    /* JSONValue[] */this.array = optional_array === undefined ? [] : optional_array;
};

/* JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype._add = function (/* JSONTypes */type, /* Object */value)
{
    this.array[this.array.length] = new org.webpki.json.JSONValue (type, value);
    return this;
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setString = function (/* String */value)
{
    return this._add (org.webpki.json.JSONTypes.STRING, value);
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setInt = function (/* int */value)
{
    return this._add (org.webpki.json.JSONTypes.INTEGER, org.webpki.json.JSONObjectWriter._intTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setLong = function (/* BigInteger */value)
{
    return this.setBigInteger (value.getLong ());
};

// No real support for BigDecimal but at least text parsing is performed

/* public JSONArrayWriter */ org.webpki.json.JSONArrayWriter.prototype.setBigDecimal = function (/* BigDecimal */value)
{
    return this._add (org.webpki.json.JSONTypes.DECIMAL, org.webpki.json.JSONObjectWriter._bigDecimalTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setBigInteger = function (/* BigInteger */value)
{
    return this._add (org.webpki.json.JSONTypes.INTEGER, value.toString ());
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setDouble = function (/* double */value)
{
    return this._add (org.webpki.json.JSONTypes.DOUBLE, org.webpki.json.JSONObjectWriter._doubleTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setBoolean = function (/* boolean */value)
{
    return this._add (org.webpki.json.JSONTypes.BOOLEAN, org.webpki.json.JSONObjectWriter._boolTest (value));
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setNULL = function ()
{
    return this._add (org.webpki.json.JSONTypes.NULL, "null");
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setDateTime = function (/* Date */date_time)
{
    return this.setString (date_time.toISOString ());
};

/* public JSONArrayWriter */org.webpki.json.JSONArrayWriter.prototype.setArray = function ()
{
    /* JSONValue[] */var new_array = [];
    this._add (org.webpki.json.JSONTypes.ARRAY, new_array);
    return new org.webpki.json.JSONArrayWriter (new_array);
};

/* public JSONObjectWriter */org.webpki.json.JSONArrayWriter.prototype.setObject = function ()
{
    /* JSONObject */var holder = new org.webpki.json.JSONObject ();
    this._add (org.webpki.json.JSONTypes.OBJECT, holder);
    return new org.webpki.json.JSONObjectWriter (holder);
};

/* public String */org.webpki.json.JSONArrayWriter.prototype.serializeJSONArray = function (/* JSONOutputFormats */output_format)
{
    /* JSONObject */var dummy = new org.webpki.json.JSONObject ();
    dummy._setArray (new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, this.array));
    return new org.webpki.json.JSONObjectWriter (dummy).serializeJSONObject (output_format);
};

/*================================================================*/
/*                       JSONDecoderCache                         */
/*================================================================*/

org.webpki.json.JSONDecoderCache = function ()
{
    this.cache = new Object ();
    this.check_for_unread = true;
};

org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER = '$';

org.webpki.json.JSONDecoderCache.CONTEXT_JSON              = "@context";
org.webpki.json.JSONDecoderCache.QUALIFIER_JSON            = "@qualifier";

/* void */org.webpki.json.JSONDecoderCache.prototype.addToCache = function (/* decoder */object_class)
{
    var object = new object_class ();
    if (object.getContext === undefined)
    {
        org.webpki.json.JSONError._error ('Missing mandatory method "getContext"');
    }
    if (object.readJSONData === undefined)
    {
        org.webpki.json.JSONError._error ('Missing mandatory method "readJSONData"');
    }
    var object_id = object.getContext ();
    if (object.getQualifier != undefined)
    {
        object_id += org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER + object.getQualifier ();
    }
    if (this.cache[object_id] != null)
    {
        org.webpki.json.JSONError._error ("Duplicate definition: " + object_id);
    }
    this.cache[object_id] = object_class;
};

/*void */org.webpki.json.JSONDecoderCache._checkForUnread = function (json_object)
{
    for (var i = 0; i < json_object.property_list.length; i++)
    {
        var name = json_object.property_list[i].name;
        var value = json_object.property_list[i].value;
        if (!json_object.read_flag[name])
        {
            org.webpki.json.JSONError._error ('Property "' + name + '" was never read');
        }
        if (value.type == org.webpki.json.JSONTypes.OBJECT)
        {
            org.webpki.json.JSONDecoderCache._checkForUnread (value.value);
        }
        else if (value.type == org.webpki.json.JSONTypes.ARRAY)
        {
            for (var q = 0; q < value.value.length; q++)
            {
                var object = value.value[q];
                if (object.type == org.webpki.json.JSONTypes.OBJECT)
                {
                    org.webpki.json.JSONDecoderCache._checkForUnread (object.value);
                }
            }
        }
    }
};

/* deserialized JSON object */org.webpki.json.JSONDecoderCache.prototype.parse = function (raw_json_document)
{
    var json_object_reader = org.webpki.json.JSONParser.parse (raw_json_document);
    var object_id = json_object_reader.getString (org.webpki.json.JSONDecoderCache.CONTEXT_JSON);
    var qualifier = json_object_reader.getStringConditional (org.webpki.json.JSONDecoderCache.QUALIFIER_JSON);
    if (qualifier != null)
    {
        object_id += org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER + qualifier;
    }
    var object_class = this.cache[object_id];
    if (object_class == null)
    {
        org.webpki.json.JSONError._error ("No document matching: " + object_id);
    }
    var object = new object_class ();
    object.readJSONData (json_object_reader);
    object._root = json_object_reader.root;
    if (this.check_for_unread)
    {
        org.webpki.json.JSONDecoderCache._checkForUnread (object._root);
    }
    return object;
};

/* void */org.webpki.json.JSONDecoderCache.prototype.setCheckForUnreadProperties = function (/* boolean */flag)
{
    this.check_for_unread = flag;
};

/*================================================================*/
/*                           JSONError                            */
/*================================================================*/

org.webpki.json.JSONError = function ()
{
};

org.webpki.json.JSONError._error = function (message)
{
    throw "JSONException: " + message;
};

/*================================================================*/
/*                           JSONObject                           */
/*================================================================*/

org.webpki.json.JSONObject = function ()
{
    this.property_list = [];
    this.read_flag = new Object ();
};

/* void */org.webpki.json.JSONObject.prototype._setProperty = function (/* String */name, /* JSONValue */value)
{
    if (!(value instanceof org.webpki.json.JSONValue))
    {
        org.webpki.json.JSONError._error ("Wrong value type: " + value);
    }
    var length = this.property_list.length;
    var new_property = new Object;
    new_property.name = name;
    new_property.value = value;
    for (var i = 0; i < length; i++)
    {
        if (this.property_list[i].name == name)
        {
            // For setupForRewrite
            if (this.property_list[i].value == null)
            {
                length = i;
                break;
            }
            org.webpki.json.JSONError._error ("Property already defined: " + name);
        }
    }
    this.property_list[length] = new_property;
    this.read_flag[name] = null;
};

/* JSONValue */org.webpki.json.JSONObject.prototype._getProperty = function (name)
{
    var length = this.property_list.length;
    for (var i = 0; i < length; i++)
    {
        if (this.property_list[i].name == name)
        {
            return this.property_list[i].value;
        }
    }
    return null;
};

/* boolean */org.webpki.json.JSONObject.prototype._isArray = function ()
{
    return this.property_list.length == 1 && !this.property_list[0].name;
};

/* void */org.webpki.json.JSONObject.prototype._setArray = function (/* JSONValue */array)
{
    this.property_list = [];
    var unnamed_property = new Object;
    unnamed_property.name = null;
    unnamed_property.value = array;
    this.property_list[0] = unnamed_property;
};

/*================================================================*/
/*                        JSONObjectReader                        */
/*================================================================*/

org.webpki.json.JSONObjectReader = function (/* JSONObject */root)
{
    this.root = root;
};

/* JSONValue */org.webpki.json.JSONObjectReader.prototype._getProperty = function (/* String */name, /* JSONTypes */expected_type)
{
    /* JSONValue */var value = this.root._getProperty (name);
    if (value == null)
    {
        org.webpki.json.JSONError._error ("Property \"" + name + "\" is missing");
    }
    if (!expected_type.isCompatible (value.type))
    {
        org.webpki.json.JSONError._error ("Type mismatch for \"" + name +
                           "\": Read=" + org.webpki.json.JSONTypes.getJSONTypeName (value.type) +
                           ", Expected=" + org.webpki.json.JSONTypes.getJSONTypeName (expected_type));
    }
    this.root.read_flag[name] = true;
    return value;
};

/* String */org.webpki.json.JSONObjectReader.prototype._getString = function (/* String */name, /* JSONTypes */expected)
{
    /* JSONValue */var value = this._getProperty (name, expected);
    return /* String */value.value;
};

/* public String */org.webpki.json.JSONObjectReader.prototype.getString = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.STRING);
};

/* public int */org.webpki.json.JSONObjectReader.prototype.getInt = function (/* String */name)
{
    return parseInt (this._getString (name, org.webpki.json.JSONTypes.INTEGER));
};

/* public BigInteger */org.webpki.json.JSONObjectReader.prototype.getLong = function (/* String */name)
{
    return this.getBigInteger (name).getLong ();
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.getBoolean = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.BOOLEAN) == "true";
};

/* public GregorianCalendar */org.webpki.json.JSONObjectReader.prototype.getDateTime = function (/* String */name)
{
    return new Date (this.getString (name));
};

/* Uint8Array */org.webpki.json.JSONObjectReader.prototype.getBinary = function (/* String */name)
{
    return org.webpki.util.Base64URL.decode (this.getString (name));
};

/* public BigInteger */org.webpki.json.JSONObjectReader.prototype.getBigInteger = function (/* String */name)
{
    return org.webpki.math.BigInteger.fromString (this._getString (name, org.webpki.json.JSONTypes.INTEGER));
};

// No real support for BigDecimal but at least text parsing is performed

/* public BigDecimal */org.webpki.json.JSONObjectReader.prototype.getBigDecimal = function (/* String */name)
{
    return this._getString (name, org.webpki.json.JSONTypes.DECIMAL);
};


/* public double */org.webpki.json.JSONObjectReader.prototype.getDouble = function (/* String */name)
{
    return parseFloat (this._getString (name, org.webpki.json.JSONTypes.DOUBLE));
};

/* public JSONArrayReader */org.webpki.json.JSONObjectReader.prototype.getJSONArrayReader = function ()
{
    return this.root._isArray () ?  new org.webpki.json.JSONArrayReader (/* JSONValue[] */this.root.property_list[0].value.value) : null;
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.getIfNULL = function (/* String */name)
{
    if (this.getPropertyType (name) == org.webpki.json.JSONTypes.NULL)
    {
        this.scanAway (name);
        return true;
    }
    return false;
};

/* public JSONObjectReader */org.webpki.json.JSONObjectReader.prototype.getObject = function (/* String */name)
{
    /* JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.OBJECT);
    return new org.webpki.json.JSONObjectReader (/* JSONObject */value.value);
};

/* public JSONArrayReader */org.webpki.json.JSONObjectReader.prototype.getArray = function (/* String */name)
{
    /* JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.ARRAY);
    return new org.webpki.json.JSONArrayReader (/* JSONValue[] */value.value);
};

 /* public String */org.webpki.json.JSONObjectReader.prototype.getStringConditional = function (/* String */name, /* String */optional_default_value)
{
    if (this.hasProperty (name))
    {
        return this.getString (name);
    }
    return optional_default_value === undefined ? null : optional_default_value;
};
 
/* public boolean */org.webpki.json.JSONObjectReader.prototype.getBooleanConditional = function (/* String */name, /* boolean */optional_default_value)
{
    if (hasProperty (name))
    {
        return getBoolean (name);
    }
    return optional_default_value === undefined ? false : optional_default_value;
};

/* Uint8Array */org.webpki.json.JSONObjectReader.prototype.getBinaryConditional = function (/* String */name)
{
    return this.hasProperty (name) ? this.getBinary (name) : null;
};

/* public String[] */org.webpki.json.JSONObjectReader.prototype.getStringArrayConditional = function (/* String */name)
{
    return this.hasProperty (name) ? this.getStringArray (name) : null;
};

/* JSONValue[] */org.webpki.json.JSONObjectReader.prototype._getArray = function (/* String */name, /* JSONTypes */expected)
{
    /* JSONValue */var value = this._getProperty (name, org.webpki.json.JSONTypes.ARRAY);
    /* JSONValue[] */var array = /* JSONValue[] */value.value;
    if (array.length > 0 && array[0].type != expected)
    {
        org.webpki.json.JSONError._error ("Array type mismatch for \"" + name + "\"");
    }
    return array;
};

/* String [] */org.webpki.json.JSONObjectReader.prototype._getSimpleArray = function (/* String */name, /* JSONTypes */expected)
{
    /* String[] */var array = [];
    var in_arr = this._getArray (name, expected);
    for (var i = 0; i < in_arr.length; i++)
    {
        array[i] = in_arr[i].value;
    }
    return array;
};

/* public String[] */org.webpki.json.JSONObjectReader.prototype.getStringArray = function (/* String */name)
{
    return this._getSimpleArray (name, org.webpki.json.JSONTypes.STRING);
};
 
 /* public Unit8Array[] */org.webpki.json.JSONObjectReader.prototype.getBinaryArray = function (/* String */name)
{
    /* Unit8Array[] */var blobs = [];
    var in_arr = this.getStringArray (name);
    for (var i = 0; i < in_arr.length; i++)
    {
        blobs[i] = org.webpki.util.Base64URL.decode (in_arr[i]);
    }
     return blobs;
};

/* public String[] */org.webpki.json.JSONObjectReader.prototype.getProperties = function ()
{
    var properties = [];
    for (var i = 0; i < this.root.property_list.length; i++)
    {
        properties[i] = this.root.property_list[i].name;
    }
    return properties;
};

/* public boolean */org.webpki.json.JSONObjectReader.prototype.hasProperty = function (/* String */name)
{
    return this.root._getProperty (name) != null;
};
 
/* public JSONTypes */org.webpki.json.JSONObjectReader.prototype.getPropertyType = function (/* String */name)
{
    /* JSONValue */var value = this.root._getProperty (name);
    return value == null ? null : value.type;
};

/**
 * Read and decode JCS signature object from the current JSON object.
 * Returns a object which can be used to verify keys etc.
 */
/* public JSONSignatureDecoder */org.webpki.json.JSONObjectReader.prototype.getSignature = function ()
{
    return new org.webpki.json.JSONSignatureDecoder (this);
};

/* public PublicKey/Uint8Array */org.webpki.json.JSONObjectReader.prototype.getPublicKey = function ()
{
    return org.webpki.json.JSONSignatureDecoder._getPublicKey (this);
};

/* public X509Certificate[]/Uint8Array[] */org.webpki.json.JSONObjectReader.prototype.getX509CertificatePath = function ()
{
    return org.webpki.json.JSONSignatureDecoder._getX509CertificatePath (this);
};

/* public void */org.webpki.json.JSONObjectReader.prototype.scanAway = function (/* String */name)
{
    this._getProperty (name, this.getPropertyType (name));
};

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

org.webpki.json.JSONObjectWriter.canonicalization_debug_mode = false;
    
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

org.webpki.json.JSONObjectWriter.prototype._writeCryptoBinary = function (/* Uint8Array */value,  /* String */name)
{
    while (value.length > 1 && value[0] == 0x00)  // Could some EC parameters actually need more than one turn?
    {
        value = new Uint8Array (value.subarray (1));
    }
    this.setBinary (name, value);
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setSignature = function (/* JSONSigner */signer)
{
    var signature_writer = this.setObject (org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON);
    signature_writer.setString (org.webpki.json.JSONSignatureDecoder.ALGORITHM_JSON, signer.getAlgorithm ());
    var key_info_writer = signature_writer.setObject (org.webpki.json.JSONSignatureDecoder.KEY_INFO_JSON);
    switch (signer.getSignatureType ())
    {
        case org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY:
             key_info_writer.setPublicKey (signer.getPublicKey ());
             break;

        case org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY:
            key_info_writer.setString (org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON, signer.getKeyID ());
            break;

        case org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE:
            key_info_writer.setX509CertificatePath (signer.getX509CertificatePath ());
            break;

        default:
            org.webpki.json.JSONError._error ("Unknown signature type requested");
     }
            
//    if (signer.getExtensions != null)
    //    {
    //        var array = /* new JSONValue */[];
    //            for (org.webpki.json.JSONObjectWriter jor : signer.extensions)
    //              {
    //                array.add (new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, jor.root));
    //              }
    //            signature_writer.setProperty (JSONSignatureDecoder.EXTENSIONS_JSON, new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, array));
    //          }
    //        
    //      }
    signature_writer.setBinary (org.webpki.json.JSONSignatureDecoder.SIGNATURE_VALUE_JSON,
                                signer.signData (org.webpki.json.JSONObjectWriter._getCanonicalizedSubset (this.root)));
    return this;
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setPublicKey = function (/* Uint8Array */public_key_in_x509_format)
{
    /* JSONObjectWriter */var public_key_writer = this.setObject (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON);
    var key_alg = new org.webpki.crypto.decodePublicKey (public_key_in_x509_format);
    if (key_alg.rsa_flag)
    {
        /* JSONObjectWriter */var rsa_key_writer = public_key_writer.setObject (org.webpki.json.JSONSignatureDecoder.RSA_JSON);
        rsa_key_writer._writeCryptoBinary (key_alg.modulus, org.webpki.json.JSONSignatureDecoder.MODULUS_JSON);
        rsa_key_writer._writeCryptoBinary (key_alg.exponent, org.webpki.json.JSONSignatureDecoder.EXPONENT_JSON);
    }
    else
    {
        /* JSONObjectWriter */var ec_key_writer = public_key_writer.setObject (org.webpki.json.JSONSignatureDecoder.EC_JSON);
        ec_key_writer.setString (org.webpki.json.JSONSignatureDecoder.NAMED_CURVE_JSON, this.xml_dsig_named_curve ?
                                                            org.webpki.crypto.XML_DSIG_CURVE_PREFIX + key_alg.oid : key_alg.uri);
        ec_key_writer._writeCryptoBinary (key_alg.x, org.webpki.json.JSONSignatureDecoder.X_JSON);
        ec_key_writer._writeCryptoBinary (key_alg.y, org.webpki.json.JSONSignatureDecoder.Y_JSON);
    }
    return this;
};

/* JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setXMLDSigECCurveOption = function (/* boolean */flag)
{
    this.xml_dsig_named_curve = flag;
    return this;
};

/* public JSONObjectWriter */org.webpki.json.JSONObjectWriter.prototype.setX509CertificatePath = function (/* X509Certificate[] */certificate_path)
{
/*
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
*/
    var certificates = certificate_path;  // Note: the above is still missing...
    this.setBinaryArray (org.webpki.json.JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON, certificates);
    return this;
};

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

/* static Uint8Array */org.webpki.json.JSONObjectWriter._getCanonicalizedSubset = function (/*JSONObject */signature_object_in)
{
    /* JSONObjectWriter */var writer = new org.webpki.json.JSONObjectWriter (signature_object_in);
    /* String*/var result = writer.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED);
    if (org.webpki.json.JSONObjectWriter.canonicalization_debug_mode)
    {
        console.debug ("Canonicalization debug:\n" + result);
    }
    return org.webpki.util.ByteArray.convertStringToUTF8 (result);
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

/* public static String */org.webpki.json.JSONObjectWriter.serializeParsedJSONDocument = function (/* JSONDecoderCache.parse() */ document, /* JSONOutputFormats */output_format)
{
    return new org.webpki.json.JSONObjectWriter (document._root).serializeJSONObject (output_format);
};
  
/* public static void */org.webpki.json.JSONObjectWriter.setCanonicalizationDebugMode = function (/* boolean */flag)
{
    org.webpki.json.JSONObjectWriter.canonicalization_debug_mode = flag;
};

/* public static string */org.webpki.json.JSONObjectWriter.parseAndFormat = function (/* String */json_string, /* JSONOutputFormats */output_format)
{
    return new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse (json_string)).serializeJSONObject (output_format);
};

/*================================================================*/
/*                        JSONOutputFormats                       */
/*================================================================*/

org.webpki.json.JSONOutputFormats = 
{
    CANONICALIZED:
    {
    },
    JAVASCRIPT_STRING:
    {
    },
    PRETTY_PRINT:
    {
    },
    PRETTY_HTML:
    {
    }
};

/*================================================================*/
/*                           JSONParser                           */
/*================================================================*/

org.webpki.json.JSONParser = function ()
{
};

org.webpki.json.JSONParser.LEFT_CURLY_BRACKET  = '{';
org.webpki.json.JSONParser.RIGHT_CURLY_BRACKET = '}';
org.webpki.json.JSONParser.BLANK_CHARACTER     = ' ';
org.webpki.json.JSONParser.DOUBLE_QUOTE        = '"';
org.webpki.json.JSONParser.COLON_CHARACTER     = ':';
org.webpki.json.JSONParser.LEFT_BRACKET        = '[';
org.webpki.json.JSONParser.RIGHT_BRACKET       = ']';
org.webpki.json.JSONParser.COMMA_CHARACTER     = ',';
org.webpki.json.JSONParser.BACK_SLASH          = '\\';

org.webpki.json.JSONParser.INTEGER_PATTERN         = new RegExp ("^((0)|(-?[1-9][0-9]*))$");
org.webpki.json.JSONParser.BOOLEAN_PATTERN         = new RegExp ("^(true|false)$");
org.webpki.json.JSONParser.DECIMAL_INITIAL_PATTERN = new RegExp ("^((\\+|-)?[0-9]+[\\.][0-9]+)$");
org.webpki.json.JSONParser.DECIMAL_2DOUBLE_PATTERN = new RegExp ("^((\\+.*)|([-][0]*[\\.][0]*))$");
org.webpki.json.JSONParser.DOUBLE_PATTERN          = new RegExp ("^([-+]?(([0-9]*\\.?[0-9]+)|([0-9]+\\.?[0-9]*))([eE][-+]?[0-9]+)?)$");

/* JSONObjectReader */org.webpki.json.JSONParser.parse = function (/* String */json_string)
{
    var parser = new org.webpki.json.JSONParser ();
    parser.json_data = json_string;
    parser.max_length = json_string.length;
    parser.index = 0;
    var root = new org.webpki.json.JSONObject ();
    if (parser._testNextNonWhiteSpaceChar () == org.webpki.json.JSONParser.LEFT_BRACKET)
    {
        parser._scan ();
        root._setArray (parser._scanArray ("outer array"));
    }
    else
    {
        parser._scanFor (org.webpki.json.JSONParser.LEFT_CURLY_BRACKET);
        parser._scanObject (root);
    }
    while (parser.index < parser.max_length)
    {
        if (!parser._isWhiteSpace (parser.json_data.charAt (parser.index++)))
        {
            org.webpki.json.JSONError._error ("Improperly terminated JSON object");
        }
    }
    return new org.webpki.json.JSONObjectReader (root);
};

/* String */org.webpki.json.JSONParser.prototype._scanProperty = function ()
{
    this._scanFor (org.webpki.json.JSONParser.DOUBLE_QUOTE);
    var property = this._scanQuotedString ().value;
    if (property.length == 0)
    {
        org.webpki.json.JSONError._error ("Empty property");
    }
    this._scanFor (org.webpki.json.JSONParser.COLON_CHARACTER);
    return property;
};

/* JSONValue */org.webpki.json.JSONParser.prototype._scanObject = function (/* JSONObject */holder)
{
    /* boolean */var next = false;
    while (this._testNextNonWhiteSpaceChar () != org.webpki.json.JSONParser.RIGHT_CURLY_BRACKET)
    {
        if (next)
        {
            this._scanFor (org.webpki.json.JSONParser.COMMA_CHARACTER);
        }
        next = true;
        /* String */var name = this._scanProperty ();
        /* JSONValue */var value;
        switch (this._scan ())
        {
            case org.webpki.json.JSONParser.LEFT_CURLY_BRACKET:
                value = this._scanObject (new org.webpki.json.JSONObject ());
                break;

            case org.webpki.json.JSONParser.DOUBLE_QUOTE:
                value = this._scanQuotedString ();
                break;

            case org.webpki.json.JSONParser.LEFT_BRACKET:
                value = this._scanArray (name);
                break;

            default:
                value = this._scanSimpleType ();
        }
        holder._setProperty (name, value);
    }
    this._scan ();
    return new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, holder);
};

/* JSONValue */org.webpki.json.JSONParser.prototype._scanArray = function (/* String */name)
{
    var arr_index = 0;
    /* JSONValue[] */var array = [];
    /* JSONValue */var value = null;
    /* boolean */var next = false;
    while (this._testNextNonWhiteSpaceChar () != org.webpki.json.JSONParser.RIGHT_BRACKET)
    {
        if (next)
        {
            this._scanFor (org.webpki.json.JSONParser.COMMA_CHARACTER);
        }
        else
        {
            next = true;
        }
        switch (this._scan ())
        {
            case org.webpki.json.JSONParser.LEFT_BRACKET:
                value = this._scanArray (name);
                break;

            case org.webpki.json.JSONParser.LEFT_CURLY_BRACKET:
                value = this._scanObject (new org.webpki.json.JSONObject ());
                break;

            case org.webpki.json.JSONParser.DOUBLE_QUOTE:
                value = this._scanQuotedString ();
                break;

            default:
                value = this._scanSimpleType ();
        }
        array[arr_index++] = value;
    }
    this._scan ();
    return new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.ARRAY, array);
};

/* JSONValue */org.webpki.json.JSONParser.prototype._scanSimpleType = function ()
{
    this.index--;
    /* String */var result = new String ();
    /* char */var c;
    while ((c = this._testNextNonWhiteSpaceChar ()) != org.webpki.json.JSONParser.COMMA_CHARACTER &&
            c != org.webpki.json.JSONParser.RIGHT_BRACKET &&
            c != org.webpki.json.JSONParser.RIGHT_CURLY_BRACKET)
    {
        if (this._isWhiteSpace (c = this._nextChar ()))
        {
            break;
        }
        result += c;
    }
    if (result.length == 0)
    {
        org.webpki.json.JSONError._error ("Missing argument");
    }
    /* JSONTypes */var type = org.webpki.json.JSONTypes.INTEGER;
    if (!org.webpki.json.JSONParser.INTEGER_PATTERN.test (result))
    {
        if (org.webpki.json.JSONParser.BOOLEAN_PATTERN.test (result))
        {
            type = org.webpki.json.JSONTypes.BOOLEAN;
        }
        else if (result == "null")
        {
            type = org.webpki.json.JSONTypes.NULL;
        }
        else if (org.webpki.json.JSONParser.DECIMAL_INITIAL_PATTERN.test (result))
        {
            type = org.webpki.json.JSONParser.DECIMAL_2DOUBLE_PATTERN.test (result) ? org.webpki.json.JSONTypes.DOUBLE : org.webpki.json.JSONTypes.DECIMAL;
        }
        else
        {
            type = org.webpki.json.JSONTypes.DOUBLE;
            if (!org.webpki.json.JSONParser.DOUBLE_PATTERN.test (result))
            {
                org.webpki.json.JSONError._error ("Undecodable argument: " + result);
            }
        }
    }
    return new org.webpki.json.JSONValue (type, result);
};

/* JSONValue */org.webpki.json.JSONParser.prototype._scanQuotedString = function ()
{
    var result = new String ();
    while (true)
    {
        /* char */var c = this._nextChar ();
        if (c < ' ')
        {
            org.webpki.json.JSONError._error ("Unescaped control character: " + c);
        }
        if (c == org.webpki.json.JSONParser.DOUBLE_QUOTE)
        {
            break;
        }
        if (c == org.webpki.json.JSONParser.BACK_SLASH)
        {
            switch (c = this._nextChar ())
            {
                case '"':
                case '\\':
                case '/':
                    break;

                case 'b':
                    c = '\b';
                    break;

                case 'f':
                    c = '\f';
                    break;

                case 'n':
                    c = '\n';
                    break;

                case 'r':
                    c = '\r';
                    break;

                case 't':
                    c = '\t';
                    break;

                case 'u':
                    var unicode_char = 0;
                    for (var i = 0; i < 4; i++)
                    {
                        unicode_char = ((unicode_char << 4) + this._getHexChar ());
                    }
                    c = String.fromCharCode (unicode_char);
                    break;

                default:
                    org.webpki.json.JSONError._error ("Unsupported escape:" + c);
            }
        }
        result += c;
    }
    return new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.STRING, result);
};

/* int */org.webpki.json.JSONParser.prototype._getHexChar = function ()
{
    /* char */var c = this._nextChar ();
    switch (c)
    {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return c.charCodeAt (0) - 48;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return c.charCodeAt (0) - 87;

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return c.charCodeAt (0) - 55;
    }
    org.webpki.json.JSONError._error ("Bad hex in \\u escape: " + c);
};

/* char */org.webpki.json.JSONParser.prototype._testNextNonWhiteSpaceChar = function ()
{
    /* int */var save = this.index;
    /* char */var c = this._scan ();
    this.index = save;
    return c;
};

/* void */org.webpki.json.JSONParser.prototype._scanFor = function (/* char */expected)
{
    /* char */var c = this._scan ();
    if (c != expected)
    {
        org.webpki.json.JSONError._error ("Expected '" + expected + "' but got '" + c + "'");
    }
};

/* char */org.webpki.json.JSONParser.prototype._nextChar = function ()
{
    if (this.index < this.max_length)
    {
        return this.json_data.charAt (this.index++);
    }
    org.webpki.json.JSONError._error ("Unexpected EOF reached");
};

/* boolean */org.webpki.json.JSONParser.prototype._isWhiteSpace = function (/* char */c)
{
    return c <= org.webpki.json.JSONParser.BLANK_CHARACTER;
};

/* char */org.webpki.json.JSONParser.prototype._scan = function ()
{
    while (true)
    {
        /* char */var c = this._nextChar ();
        if (this._isWhiteSpace (c))
        {
            continue;
        }
        return c;
    }
};

/*================================================================*/
/*                       JSONSignatureDecoder                     */
/*================================================================*/

org.webpki.json.JSONSignatureDecoder = function (/* JSONObjectReader */rd) 
{
    var signature = rd.getObject (org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON);
    var version = signature.getStringConditional (org.webpki.json.JSONSignatureDecoder.VERSION_JSON,
                                                  org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID);
    if (version != org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID)
    {
        org.webpki.json.JSONError._error ("Unknown \"" + org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON + "\" version: " + version);
    }
    this._signature_algorithm = signature.getString (org.webpki.json.JSONSignatureDecoder.ALGORITHM_JSON);
    this._getKeyInfo (signature.getObject (org.webpki.json.JSONSignatureDecoder.KEY_INFO_JSON));
    this._extensions = null;
    if (signature.hasProperty (org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON))
    {
        var ext_arr_reader = signature.getArray (org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON);
        this._extensions = [];
        do
        {
            var ext_obj = ext_arr_reader.getObject ();
            if (!ext_obj.hasProperty (org.webpki.json.JSONSignatureDecoder.TYPE_JSON))
            {
                org.webpki.json.JSONError._error ("An \"" + org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON + "\" object lack a \"" + org.webpki.json.JSONSignatureDecoder.TYPE_JSON + "\" property");
            }
            this._extensions[this._extensions.length] = ext_obj;
        }
        while (ext_arr_reader.hasMore ());
    }
    this._signature_value = signature.getBinary (org.webpki.json.JSONSignatureDecoder.SIGNATURE_VALUE_JSON);
    var save = signature.root.property_list;
    var new_list = [];
    for (var i = 0; i < save.length; i++)
    {
        if (save[i].name != org.webpki.json.JSONSignatureDecoder.SIGNATURE_VALUE_JSON)
        {
            new_list[new_list.length] = save[i];
        }
    }
    signature.root.property_list = new_list;
    this._canonicalized_data = org.webpki.json.JSONObjectWriter._getCanonicalizedSubset (rd.root);
    signature.root.property_list = save;
};

org.webpki.json.JSONSignatureDecoder.ALGORITHM_JSON             = "Algorithm";

org.webpki.json.JSONSignatureDecoder.EC_JSON                    = "EC";

org.webpki.json.JSONSignatureDecoder.EXPONENT_JSON              = "Exponent";

org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON            = "Extensions";

org.webpki.json.JSONSignatureDecoder.ISSUER_JSON                = "Issuer";

org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON                = "KeyID";

org.webpki.json.JSONSignatureDecoder.KEY_INFO_JSON              = "KeyInfo";

org.webpki.json.JSONSignatureDecoder.MODULUS_JSON               = "Modulus";

org.webpki.json.JSONSignatureDecoder.NAMED_CURVE_JSON           = "NamedCurve";

org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON            = "PublicKey";

org.webpki.json.JSONSignatureDecoder.RSA_JSON                   = "RSA";

org.webpki.json.JSONSignatureDecoder.SERIAL_NUMBER_JSON         = "SerialNumber";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON             = "Signature";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON = "SignatureCertificate";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_VALUE_JSON       = "SignatureValue";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";

org.webpki.json.JSONSignatureDecoder.SUBJECT_JSON               = "Subject";

org.webpki.json.JSONSignatureDecoder.TYPE_JSON                  = "Type";

org.webpki.json.JSONSignatureDecoder.URL_JSON                   = "URL";

org.webpki.json.JSONSignatureDecoder.VERSION_JSON               = "Version";

org.webpki.json.JSONSignatureDecoder.X_JSON                     = "X";

org.webpki.json.JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON = "X509CertificatePath";

org.webpki.json.JSONSignatureDecoder.Y_JSON                     = "Y";

/* void */org.webpki.json.JSONSignatureDecoder.prototype._getKeyInfo = function (/* JSONObjectReader */rd)
{
    if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON))
    {
        this._readX509CertificateEntry (rd);
    }
    else if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON))
    {
        this._public_key = org.webpki.json.JSONSignatureDecoder._getPublicKey (rd);
    }
    else if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON))
    {
        this._key_id = rd.getString (org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON);
    }
    else if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.URL_JSON))
    {
        org.webpki.json.JSONError._error ("\"" + org.webpki.json.JSONSignatureDecoder.URL_JSON + "\" not yet implemented");
    }
    else
    {
        org.webpki.json.JSONError._error ("Undecodable \"" + org.webpki.json.JSONSignatureDecoder.KEY_INFO_JSON + "\" object");
    }
};

/* static Uint8Array */org.webpki.json.JSONSignatureDecoder._readCryptoBinary = function (/* JSONObjectReader */rd, /* String */property)
{
    var crypto_binary = rd.getBinary (property);
    if (crypto_binary[0] == 0x00)
    {
        org.webpki.json.JSONError._error ("Public key parameters must not contain leading zeroes");
    }
    return crypto_binary;
};

/* Uint8Array */org.webpki.json.JSONSignatureDecoder._getPublicKey = function (/* JSONObjectReader */rd)
{
    rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON);
    if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.RSA_JSON))
    {
        rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.RSA_JSON);
        return org.webpki.crypto.encodeRSAPublicKey 
            (org.webpki.json.JSONSignatureDecoder._readCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.MODULUS_JSON),
             org.webpki.json.JSONSignatureDecoder._readCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.EXPONENT_JSON));
    }
    rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.EC_JSON);
    return org.webpki.crypto.encodeECPublicKey 
        (rd.getString (org.webpki.json.JSONSignatureDecoder.NAMED_CURVE_JSON),
         org.webpki.json.JSONSignatureDecoder._readCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.X_JSON),
         org.webpki.json.JSONSignatureDecoder._readCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.Y_JSON));
};

/* public Uint8Array */org.webpki.json.JSONSignatureDecoder.prototype.getCanonicalizedData = function ()
{
    return this._canonicalized_data;
};

/* public Uint8Array */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureValue = function ()
{
    return this._signature_value;
};

/* public String */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureAlgorithm = function ()
{
    return this._signature_algorithm;
};

/* public JSONObjectReader[] */org.webpki.json.JSONSignatureDecoder.prototype.getExtensions = function ()
{
    return this._extensions;
};

/* void */org.webpki.json.JSONSignatureDecoder.prototype._checkRequest = function (/* JSONSignatureTypes */signature_type)
{
    if (signature_type != this.getSignatureType ())
    {
        org.webpki.json.JSONError._error ("Request doesn't match received signature: " + this.getSignatureType ().toString ());
    }
};

org.webpki.json.JSONSignatureDecoder.prototype.verify = function (/* Verifier*/verifier)
{
    if (verifier.getVerifierType () != this.getSignatureType ())
    {
        org.webpki.json.JSONError._error ("Verifier type doesn't match the received signature");
    }
    if (!verifier.verify (this))
    {
        org.webpki.json.JSONError._error ("Signature didn't validate");
    }
};

/* public Uint8Array[]/X509Certificate[] */org.webpki.json.JSONSignatureDecoder.prototype.getX509CertificatePath = function ()
{
    this._checkRequest (org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE);
    return this._certificate_path;
};

/* public Uint8Array/PublicKey */org.webpki.json.JSONSignatureDecoder.prototype.getPublicKey = function ()
{
    if (this.getSignatureType () != org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE)
    {
        this._checkRequest (org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY);
    }
    return this._public_key;
};

/* public String */org.webpki.json.JSONSignatureDecoder.prototype.getKeyID = function ()
{
    this._checkRequest (org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY);
    return this._key_id;
};

/* public JSONSignatureTypes */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureType = function ()
{
    if (this._certificate_path != null)
    {
        return org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE;
    }
    return this._public_key == null ? org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY : org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY;
};

/* Uint8Array[] */org.webpki.json.JSONSignatureDecoder._getX509CertificatePath = function (/* JSONObjectReader */rd)
{
    return rd.getBinaryArray (org.webpki.json.JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON);
/*      
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryArray (X509_CERTIFICATE_PATH_JSON))
          {
            try
              {
                CertificateFactory cf = CertificateFactory.getInstance ("X.509");
                X509Certificate certificate = (X509Certificate)cf.generateCertificate (new ByteArrayInputStream (certificate_blob));
                certificates.add (pathCheck (last_certificate, last_certificate = certificate));
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        return certificates.toArray (new X509Certificate[0]);
*/
};

/* void */org.webpki.json.JSONSignatureDecoder.prototype._readX509CertificateEntry = function (/* JSONObjectReader */rd)
{
    this._certificate_path = org.webpki.json.JSONSignatureDecoder._getX509CertificatePath (rd);
    this._public_key = new org.webpki.crypto.decodeX509Certificate (this._certificate_path[0]).public_key;
    if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON))
    {
        rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON);
        var issuer = rd.getString (org.webpki.json.JSONSignatureDecoder.ISSUER_JSON);
        var serial_number = rd.getBigInteger (org.webpki.json.JSONSignatureDecoder.SERIAL_NUMBER_JSON);
        var subject = rd.getString (org.webpki.json.JSONSignatureDecoder.SUBJECT_JSON);
      /*      
      X509Certificate signature_certificate = certificate_path[0];
      if (!signature_certificate.getIssuerX500Principal ().getName ().equals (issuer) ||
          !signature_certificate.getSerialNumber ().equals (serial_number) ||
          !signature_certificate.getSubjectX500Principal ().getName ().equals (subject))
        {
          throw new IOException ("\"" + SIGNATURE_CERTIFICATE_JSON + "\" doesn't match actual certificate");
        }
*/
    }
};

/*================================================================*/
/*                       JSONSignatureTypes                       */
/*================================================================*/

org.webpki.json.JSONSignatureTypes = 
{
    X509_CERTIFICATE:
    {
        "toString": function () { return "X509 path";}
    },
    ASYMMETRIC_KEY:
    {
        "toString": function () { return "Asymmetric key";}
    },
    SYMMETRIC_KEY:
    {
        "toString": function () { return "Symmetric key";}
    }
};

/*================================================================*/
/*                            JSONTypes                           */
/*================================================================*/

org.webpki.json.JSONTypes = 
{
    NULL:
    {
        "enumvalue" : 0,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.NULL; }
    },
    BOOLEAN:
    {
        "enumvalue" : 1,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.BOOLEAN; }
    },
    INTEGER:
    {
        "enumvalue" : 2,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.INTEGER; }
    },
    DECIMAL:
    {
        "enumvalue" : 3,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.DECIMAL || o == org.webpki.json.JSONTypes.INTEGER; }
    },
    DOUBLE:
    {
        "enumvalue" : 4,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.DOUBLE || o == org.webpki.json.JSONTypes.DECIMAL || o == org.webpki.json.JSONTypes.INTEGER; }
    },
    STRING:
    {
        "enumvalue" : 5,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.STRING; }
    },
    ARRAY:
    {
        "enumvalue" : 10,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.ARRAY; }
    },
    OBJECT:
    {
        "enumvalue" : 11,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.OBJECT; }
    }
};

org.webpki.json.JSONTypes.getJSONTypeName = function (json_type)
{
    for (var obj in org.webpki.json.JSONTypes)
    {
        if (org.webpki.json.JSONTypes[obj].enumvalue == json_type.enumvalue)
        {
            return obj;
        }
    }
    return "UNKNOWN!";
};

/*================================================================*/
/*                            JSONValue                           */
/*================================================================*/

 org.webpki.json.JSONValue = function (type, value)
{
    this.type = type;
    this.value = value;
};

/*================================================================*/
/*               Namespace for the "Math" library                 */
/*================================================================*/

"use strict";

var org = org || {};
org.webpki = org.webpki || {};
org.webpki.math = org.webpki.math || {};

/*================================================================*/
/*                           BigInteger                           */
/*================================================================*/

// The JS version of BigInteger is just a thin wrapper over an "Uint8Array" and
// the only functionality offered are tests for equivalence and zero.  It is anticipated
// that all cryptographic functions are performed in other and lower layers of
// the platform.  Only positive values (and zero) are currently supported.

/* BigInteger */org.webpki.math.BigInteger = function (/* Uint8Array */optional_value)
{
    if (optional_value === undefined)
    {
        this.value = null;
    }
    else
    {
        this.value = optional_value;
        this._trim ();
    }
};

org.webpki.math.BigInteger._error = function (message)
{
    throw "MATHException: " + message;
};

/* void */org.webpki.math.BigInteger.prototype._trim = function ()
{
    var offset = 0;
    while (this.value[offset] == 0 && offset < (this.value.length - 1))
    {
        offset++;
    }
    if (offset != 0)
    {
        var trimmed = new Uint8Array (this.value.length - offset);
        for (var q = 0; q < trimmed.length; q++)
        {
            trimmed[q] = this.value[q + offset];
        }
        this.value = trimmed;
    }
};

org.webpki.math.BigInteger._base = function (/* int */optional_10_or_16_base)
{
    if (optional_10_or_16_base === undefined)
    {
        return 10;
    }
    else if (optional_10_or_16_base == 10)
    {
        return 10;
    }
    else if (optional_10_or_16_base == 16)
    {
        return 16;
    }
    else
    {
        org.webpki.math.BigInteger._error ("Incorrect base argument, only 10 and 16 are supported");
    }
    throw "MATHException: " + message;
};

/* bool*/ org.webpki.math.BigInteger._isZero = function (/* Uint8Array */byte_array)
{
    for (var i = 0; i < byte_array.length; i++)
    {
        if (byte_array[i] != 0)
        {
            return false;
        }
    }
    return true;
};

/* bool*/ org.webpki.math.BigInteger.prototype.isZero = function ()
{
    return org.webpki.math.BigInteger._isZero (this.value);
};

/* BigInteger */ org.webpki.math.BigInteger.prototype.getLong = function ()
{
    if (this.value.length > 8)
    {
        org.webpki.math.BigInteger._error ("Out of \"Long\" range");
    }
    return this;
};

/* void */org.webpki.math.BigInteger._setSmallValue = function (/* Uint8Array */byte_array, /* int*/value)
{
    var i = byte_array.length;
    byte_array[--i] = value;
    while (--i >= 0)
    {
        byte_array[i] = 0;
    }
};

/* int */org.webpki.math.BigInteger._getNextDigit = function (/* Uint8Array */dividend, /* int*/divisor)
{
    var remainder = 0;
    for (var i = 0; i < dividend.length; i++)
    {
        remainder = dividend[i] | (remainder << 8);
        dividend[i] = Math.floor (remainder / divisor);
        remainder = Math.floor (remainder % divisor);
    }
    return remainder;
};

/* BigInteger */org.webpki.math.BigInteger.fromString = function (/* String */string, /* int */optional_10_or_16_base)
{
    var base = org.webpki.math.BigInteger._base (/* int */optional_10_or_16_base);
    if (typeof string  == 'number')
    {
        string = string.toString ();
    }
    else if (typeof string  != 'string')
    {
        org.webpki.math.BigInteger._error ("Expected a string argument");
    }
    if (string.length == 0)
    {
        org.webpki.math.BigInteger._error ("Empty string not allowed");
    }
    var bi = new org.webpki.math.BigInteger ();
    var result = [];
    result[0] = 0;
    for (var i = 0; i <  string.length; i++)
    {
        var n;
        /* char */var c = string.charAt (i);
        if (c >= '0' && c <= '9')
        {
            n = c.charCodeAt (0) - 48;
        }
        else if (base == 10)
        {
            org.webpki.math.BigInteger._error ("Decimal number expected");

        }
        else if (c >= 'a' && c <= 'f')
        {
            n = c.charCodeAt (0) - 87;
        }
        else if (c >= 'A' && c <= 'F')
        {
            n = c.charCodeAt (0) - 55;
        }
        else
        {
            org.webpki.math.BigInteger._error ("Hexadecimal number expected");
        }
        var carry = 0;
        var j = 0;
        while (j < result.length)
        {
            var bigres = base * result[j] + n + carry;
            n = 0;
            bigres -= (carry = Math.floor (bigres / 256)) * 256;
            result[j++] = bigres;
            if (carry > 0 && j == result.length)
            {
                result[j] = 0;
            }
        }
    }
    bi.value = new Uint8Array (result.length);
    for (var i = 0; i < result.length; i++)
    {
        bi.value [result.length - i - 1] = result[i];
    }
    bi._trim ();
    return bi;
};

/* Uint8Array */org.webpki.math.BigInteger.prototype.getByteArray = function ()
{
    if (!this.value)
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    return this.value;
};

/* boolean */org.webpki.math.BigInteger.prototype.equals = function (/* BigInteger */big_integer)
{
    if (!this.value || !big_integer.value) 
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    return org.webpki.util.ByteArray.equals (this.value, big_integer.value);
};

/* String */org.webpki.math.BigInteger.prototype.toString = function (/* int */optional_10_or_16_base)
{
    if (!this.value)
    {
        org.webpki.math.BigInteger._error ("BigInteger not initialized");
    }
    var base = org.webpki.math.BigInteger._base (/* int */optional_10_or_16_base);

    var reversed_string = "";
    var divisor = new Uint8Array (this.value);
    do
    {
        var digit = org.webpki.math.BigInteger._getNextDigit (divisor, base);
        reversed_string += String.fromCharCode (digit + (digit > 9 ? 55 : 48));
    }
    while (!org.webpki.math.BigInteger._isZero (divisor))
  
    var result = "";
    var i = reversed_string.length;
    while (--i >= 0)
    {
        result += reversed_string.charAt (i);
    }
    return result;
};

/*================================================================*/
/*               Namespace for the "Util" library                 */
/*================================================================*/

"use strict";

var org = org || {};
org.webpki = org.webpki || {};
org.webpki.util = org.webpki.util || {};

/*================================================================*/
/*                            Base64URL                           */
/*================================================================*/

//* Encodes/decodes base64URL data as described in RFC 4648 Table 2.

org.webpki.util.Base64URL =
{
    BASE64URL :
    [//  0   1   2   3   4   5   6   7
        'A','B','C','D','E','F','G','H', // 0
        'I','J','K','L','M','N','O','P', // 1
        'Q','R','S','T','U','V','W','X', // 2
        'Y','Z','a','b','c','d','e','f', // 3
        'g','h','i','j','k','l','m','n', // 4
        'o','p','q','r','s','t','u','v', // 5
        'w','x','y','z','0','1','2','3', // 6
        '4','5','6','7','8','9','-','_'  // 7
    ],
    DECODE_TABLE :
    [
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, 62, -1, -1,
        52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6, 
         7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51
    ]
};

      ////////////////////
     ////   DECODE   //// Throws Base64Exception if argument isn't base64URL
    ////////////////////

/* Uint8Array */org.webpki.util.Base64URL.decode = function (/* String */ encoded)
{
    var semidecoded = new Uint8Array (encoded.length);
    for (var i = 0; i < encoded.length; i++)
    {
        var c = encoded.charCodeAt (i);
        if (c >= org.webpki.util.Base64URL.DECODE_TABLE.length || (c = org.webpki.util.Base64URL.DECODE_TABLE[c]) < 0)
        {
            throw "Base64Exception: bad character at index " + i;
        }
        semidecoded[i] = c;
    }
    
    var encoded_length_modulo_4 = Math.floor (encoded.length % 4);
    var decoded_length = Math.floor (encoded.length / 4) * 3;
    if (encoded_length_modulo_4 != 0)
    {
        decoded_length += encoded_length_modulo_4 - 1;
    }
    var decoded = new Uint8Array (decoded_length);
    var decoded_length_modulo_3 = Math.floor (decoded_length % 3);
    if (decoded_length_modulo_3 == 0 && encoded_length_modulo_4 != 0)
    {
        throw "Base64Exception: wrong number of characters";
    }

    // -----:  D E C O D E :-----
    var i = 0, j = 0;
    //decode in groups of four bytes
    while (j < decoded.length - decoded_length_modulo_3)
    {
        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        decoded[j++] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);
        decoded[j++] = (semidecoded[i++] << 6) | semidecoded[i++];
    }
    //decode "odd" bytes
    if (decoded_length_modulo_3 == 1)
    {
        decoded[j] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        if (semidecoded[i] & 0x0F)
        {
            throw "Base64Exception: wrong termination character";
        }
    }
    else if (decoded_length_modulo_3 == 2)
    {
        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        decoded[j] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);
        if (semidecoded[i] & 0x03)
        {
            throw "Base64Exception: wrong termination character";
        }
    }
    return decoded;
};
  
      ////////////////////
     ////   ENCODE   //// Does not throw exceptions
    ////////////////////

/* String */org.webpki.util.Base64URL.encode = function (/* Uint8Array */uncoded)
{
    var encoded = new String ();
    var i = 0;
    var modulo3 = uncoded.length % 3;
    while (i < uncoded.length - modulo3)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 4) & 0x30) | ((uncoded[i] >>> 4) & 0x0F)];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 2) & 0x3C) | ((uncoded[i] >>> 6) & 0x03)];
        encoded += org.webpki.util.Base64URL.BASE64URL[uncoded[i++] & 0x3F];
    }
    if (modulo3 == 1)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] << 4) & 0x30];
    }
    else if (modulo3 == 2)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 4) & 0x30) | ((uncoded[i] >>> 4) & 0x0F)];
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] << 2) & 0x3C];
    }
    return encoded;
};

/*================================================================*/
/*                            ByteArray                           */
/*================================================================*/

//* Encodes/decodes base64URL data as described in RFC 4648 Table 2.

org.webpki.util.ByteArray = {};

/* boolean */org.webpki.util.ByteArray.equals = function (/* Uint8Array */arg1, /* Uint8Array */arg2)
{
    if (arg1.length != arg2.length)
    {
        return false;
    }
    for (var i = 0; i < arg1.length; i++)
    {
        if (arg1[i] != arg2[i])
        {
            return false;
        }
    }
    return true;
};

/* Uint8Array */org.webpki.util.ByteArray.convertStringToUTF8 = function (/* String */string)
{
    var buffer = [];
    for (var n = 0; n < string.length; n++)
    {
        var c = string.charCodeAt (n);
        if (c < 128) 
        {
            buffer.push (c);
        }
        else if ((c > 127) && (c < 2048))
        {
            buffer.push ((c >> 6) | 192);
            buffer.push ((c & 63) | 128);
        }
        else 
        {
            buffer.push ((c >> 12) | 224);
            buffer.push (((c >> 6) & 63) | 128);
            buffer.push ((c & 63) | 128);
        }
    }
    return new Uint8Array (buffer);
};

/* Uint8Array */org.webpki.util.ByteArray.add = function (/* Uint8Array */arg1, /* Uint8Array */arg2)
{
    var combined = new Uint8Array (arg1.length + arg2.length);
    var i = 0;
    while (i < arg1.length)
    {
        combined[i] = arg1[i++];
    }
    for (var j = 0; j < arg2.length; j++)
    {
        combined[i++] = arg2[j];
    }
    return combined;
};

/* String */ org.webpki.util.ByteArray._hex = function (/* byte */i)
{
    if (i < 10)
    {
        return String.fromCharCode (i + 48);
    }
    return String.fromCharCode (i + 55);
};

/* String */org.webpki.util.ByteArray._twohex = function (/* byte */i)
{
    return org.webpki.util.ByteArray._hex (i / 16) + org.webpki.util.ByteArray._hex (i % 16);
};

/* String */org.webpki.util.ByteArray.toHex = function (/* Uint8Array */arg)
{
    var result = "";
    for (var i = 0; i < arg.length; i++)
    {
        result += " " + org.webpki.util.ByteArray._twohex (arg[i]);
    }
    return result;
};

/*================================================================*/
/*              Namespace for the "Crypto" library                */
/*================================================================*/

"use strict";

var org = org || {};
org.webpki = org.webpki || {};
org.webpki.crypto = org.webpki.crypto || {};

/*================================================================*/
/*                       Key Serialization                        */
/*================================================================*/

org.webpki.crypto.SUPPORTED_NAMED_CURVES = 
[//                 SKS Algorithm ID                   Coordinate Length   Textual OID            ASN.1 OID (without header)
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b163",        21,     "1.3.132.0.15",         [0x2B, 0x81, 0x04, 0x00, 0x0F],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b233",        30,     "1.3.132.0.27",         [0x2B, 0x81, 0x04, 0x00, 0x1B],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b283",        36,     "1.3.132.0.17",         [0x2B, 0x81, 0x04, 0x00, 0x11],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p192",        24,     "1.2.840.10045.3.1.1",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",        32,     "1.2.840.10045.3.1.7",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",        48,     "1.3.132.0.34",         [0x2B, 0x81, 0x04, 0x00, 0x22],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",        66,     "1.3.132.0.35",         [0x2B, 0x81, 0x04, 0x00, 0x23],
    "http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1", 32,     "1.3.36.3.3.2.8.1.1.7", [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
];

org.webpki.crypto.RSA_ALGORITHM_OID    = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
org.webpki.crypto.EC_ALGORITHM_OID     = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; 

org.webpki.crypto.XML_DSIG_CURVE_PREFIX      = "urn:oid:";

org.webpki.crypto._error = function (/* String */message)
{
    throw "CryptoException: " + message;
};

/* int */org.webpki.crypto._getECParamsFromURI = function (/* String */uri)
{
    if (uri.indexOf (org.webpki.crypto.XML_DSIG_CURVE_PREFIX) == 0)
    {
        var oid = uri.substring (org.webpki.crypto.XML_DSIG_CURVE_PREFIX.length);
        for (var i = 2; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i+= 4)
        {
            if (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i] == oid)
            {
                return i - 2;
            }
        }
    }
    else
    {
        for (var i = 0; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i += 4)
        {
            if (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i] == uri)
            {
                return i;
            }
        }
    }
    org.webpki.crypto._error ("Unsupported EC curve: " + uri);
};

/* Uint8Array */org.webpki.crypto.leftPadWithZeros = function (/* int */required_length, /* Unit8Array */original)
{
    if (original.length > required_length)
    {
        org.webpki.crypto._error ("Input data out of bounds: " + original.length);        
    }
    while (original.length < required_length)
    {
        original = org.webpki.util.ByteArray.add ([0x00], original);
    }
    return original;
};

/* Uint8Array */org.webpki.crypto.encodeECPublicKey = function (/* String */url, /* Uint8Array */x, /* Uint8Array */y)
{
    var params_entry = org.webpki.crypto._getECParamsFromURI (url);
    var coordinate_length = org.webpki.crypto.SUPPORTED_NAMED_CURVES[params_entry + 1];
    return new org.webpki.asn1.ASN1Object
      (
        org.webpki.asn1.TAGS.SEQUENCE,
        new org.webpki.asn1.ASN1Object
          (
            org.webpki.asn1.TAGS.SEQUENCE,
            new org.webpki.asn1.ASN1Object
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.EC_ALGORITHM_OID
              )
          )
        .addComponent 
          (
            new org.webpki.asn1.ASN1Object 
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.SUPPORTED_NAMED_CURVES[params_entry + 3]
              )
          )
      )
    .addComponent
      (
        new org.webpki.asn1.ASN1Object 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            org.webpki.util.ByteArray.add 
              (
                [0x00, 0x04],
                org.webpki.util.ByteArray.add
                  (
                    org.webpki.crypto.leftPadWithZeros (coordinate_length, x),
                    org.webpki.crypto.leftPadWithZeros (coordinate_length, y)
                  )
              )
          )
      ).encode ();
};

/* Uint8Array */org.webpki.crypto.encodeRSAPublicKey = function (/* Uint8Array */modulus, /* Uint8Array */exponent)
{
    return new org.webpki.asn1.ASN1Object
      (
        org.webpki.asn1.TAGS.SEQUENCE,
        new org.webpki.asn1.ASN1Object
          (
            org.webpki.asn1.TAGS.SEQUENCE,
            new org.webpki.asn1.ASN1Object
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.RSA_ALGORITHM_OID
              )
          )
        .addComponent (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.NULL, []))
      )
    .addComponent
      (
        new org.webpki.asn1.ASN1Object 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            org.webpki.util.ByteArray.add 
              (
                [0],
                new org.webpki.asn1.ASN1Object
                  (
                    org.webpki.asn1.TAGS.SEQUENCE,
                    org.webpki.asn1.ASN1PositiveInteger (modulus)
                  )
                .addComponent (org.webpki.asn1.ASN1PositiveInteger (exponent)).encode ()
              )
          )
      ).encode ();
};

org.webpki.crypto.decodePublicKey = function (/* Uint8Array */spki)
{
    var outer_sequence = new org.webpki.asn1.ParsedASN1Sequence (spki);
    if (outer_sequence.numberOfComponents () != 2)
    {
        org.webpki.crypto._error ("SubjectPublicKeyInfo sequence must be two elements");        
    }
    var algorithm_id = outer_sequence.getComponent (0).getASN1Sequence ();
    if (algorithm_id.numberOfComponents () != 2)
    {
        org.webpki.crypto._error ("Algorithm ID sequence must be two elements");        
    }
    var public_key_type = algorithm_id.getComponent (0).getASN1ObjectIDRawData ();
    var encapsulated_key = outer_sequence.getComponent (1).getASN1BitString (true);
    if ((this.rsa_flag = org.webpki.util.ByteArray.equals (public_key_type, org.webpki.crypto.RSA_ALGORITHM_OID)))
    {
        algorithm_id.getComponent (1).getASN1NULL ();
        var rsa_params = new org.webpki.asn1.ParsedASN1Sequence (encapsulated_key);
        if (rsa_params.numberOfComponents () != 2)
        {
            org.webpki.crypto._error ("RSA parameter sequence must be two elements");        
        }
        this.modulus = rsa_params.getComponent (0).getASN1PositiveInteger ();
        this.exponent = rsa_params.getComponent (1).getASN1PositiveInteger ();
    }
    else if (org.webpki.util.ByteArray.equals (public_key_type, org.webpki.crypto.EC_ALGORITHM_OID))
    {
        if (encapsulated_key[0] != 0x04)
        {
            org.webpki.crypto._error ("EC uncompressed parameter expected");        
        }
        var ec_curve = algorithm_id.getComponent (1).getASN1ObjectIDRawData ();
        for (var i = 3; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i += 4)
        {
            if (org.webpki.util.ByteArray.equals (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i], ec_curve))
            {
                var coordinate_length = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 2];
                if (encapsulated_key.length != coordinate_length * 2 + 1)
                {
                    org.webpki.crypto._error ("ECPoint length error");        
                }
                this.x = new Uint8Array (encapsulated_key.subarray (1, 1 + coordinate_length));
                this.y = new Uint8Array (encapsulated_key.subarray (1 + coordinate_length));
                this.uri = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 3];
                this.oid = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 1];
                return;
            }
        }
        org.webpki.crypto._error ("EC curve OID unknown");        
    }
    else
    {
        org.webpki.crypto._error ("Public key OID unknown");        
    }
};

/* String */org.webpki.crypto.getDistinguishedName = function (asn1_sequence)
{
    var holder = asn1_sequence.getASN1Sequence ();
    var dn = "";
    for (var i = 0; i < holder.numberOfComponents (); i++)
    {
        var set = holder.getComponent (i).getASN1Set ();
        if (set.numberOfComponents () != 1)
        {
            return null;
        }
        var attr = set.getComponent (0).getASN1Sequence ();
        if (attr.numberOfComponents () != 1)
        {
            return null;
        }
    }
    return dn;
};

/* certificate data */org.webpki.crypto.decodeX509Certificate = function(/* Uint8Array */certificate_blob)
{
    var asn1 = new org.webpki.asn1.ParsedASN1Sequence (certificate_blob);
    var tbs = asn1.getComponent (0).getASN1Sequence ();
    var index = 0;
    if (tbs.getComponent (0).getTag () == org.webpki.asn1.TAGS.EXPLICIT_CONTEXT_0)
    {
        index++;  // V3
    }
    this.serial_number = new org.webpki.math.BigInteger (tbs.getComponent (index++).getASN1PositiveInteger ());
    tbs.getComponent (index++).getASN1Sequence ();  // Signature alg, skip
    this.issuer = org.webpki.crypto.getDistinguishedName (tbs.getComponent (index++));
    if (this.issuer === undefined)
    {
        console.debug ("Couldn't decode issuer DN");
    }
    if (tbs.getComponent (index++).getASN1Sequence ().numberOfComponents () != 2)
    {
        org.webpki.crypto._error ("Certificate validity not found");        
    }
    this.subject = org.webpki.crypto.getDistinguishedName (tbs.getComponent (index++));
    if (this.subject === undefined)
    {
        console.debug ("Couldn't decode subject DN");
    }
    org.webpki.crypto.decodePublicKey (this.public_key = tbs.getComponent (index++).getASN1Sequence ().encode ());
};

/*================================================================*/
/*               Namespace for the "ASN1" library                 */
/*================================================================*/

"use strict";

var org = org || {};
org.webpki = org.webpki || {};
org.webpki.asn1 = org.webpki.asn1 || {};

/*================================================================*/
/*                            ASN1                                */
/*================================================================*/

org.webpki.asn1.TAGS =
{
    OID                : 0x06,
    SEQUENCE           : 0x30,
    SET                : 0x31,
    INTEGER            : 0x02,
    NULL               : 0x05,
    BITSTRING          : 0x03,
    EXPLICIT_CONTEXT_0 : 0xA0,
    EXPLICIT_CONTEXT_1 : 0xA1,
    EXPLICIT_CONTEXT_3 : 0xA3,
    OCTET_STRING       : 0x04
};

org.webpki.asn1.LIBRARY_LIMIT = 50000;  // 50k of ASN.1 is all we care of

org.webpki.asn1._error = function (/* String */message)
{
    throw "ASN1Exception: " + message;
};

/* void */org.webpki.asn1._lengthCheck = function (/* int */length)
{
    if (length > org.webpki.asn1.LIBRARY_LIMIT)
    {
        org.webpki.asn1._error ("Exceeded library limit " + org.webpki.asn1.LIBRARY_LIMIT + " bytes");
    }
};

org.webpki.asn1.ASN1Object = function (/* byte */tag, /* ASN1Object or Uint8Array */argument)
{
    this.components = [];  /* ASN1Object or Uint8Array */
    this.components[0] = argument;
    this.tag = tag;
    return this;
};

/* ASN1Object */org.webpki.asn1.ASN1Object.prototype.addComponent = function (/* ASN1Object */component)
{
    this.components[this.components.length] = component;
    return this;
};

/* Uint8Array */org.webpki.asn1.ASN1Object.prototype.encode = function ()
{
    this.encoded = new Uint8Array ();
    for (var i = 0; i < this.components.length; i++)
    {
        if (this.components[i] instanceof org.webpki.asn1.ASN1Object)
        {
            this._update (this.components[i].encode ()); 
        }
        else
        {
            this._update (this.components[i]);
        }
    }
    var body = this.encoded;
    var length = body.length;
    this.encoded = new Uint8Array ([this.tag, length & 0x7F]);
    if (length > 127)
    {
        if (length > 255)
        {
            this.encoded[1] = 0x82;
            this._update ([length >> 8]);
        }
        else
        {
            this.encoded[1] = 0x81;
        }
        this._update ([length & 0xFF]);
    }
    return this._update (body);
};

/* Uint8Array */org.webpki.asn1.ASN1Object.prototype._update = function (array)
{
    return this.encoded = org.webpki.util.ByteArray.add (this.encoded, array);
};

/* ASN1Object */org.webpki.asn1.ASN1PositiveInteger = function (/* Uint8Array */blob_integer)
{
    if (blob_integer[0] > 127)
    {
        blob_integer = org.webpki.util.ByteArray.add ([0], blob_integer);
    }
    return new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.INTEGER, blob_integer);
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1Object = function (/* Uint8Array */raw_der)
{
    org.webpki.asn1._lengthCheck (raw_der.length);
    this.raw_der = raw_der;
    this.position = 0;
    this.tag = this._readDERByte ();
//    console.debug ("TAG=" + this.tag + " RDL=" + raw_der.length + " DA=" + org.webpki.util.ByteArray.toHex (raw_der));
    var length = this._readDERByte ();
    if ((length & 0x80) != 0)
    {
        var bytes = length & 0x7F;
        length = 0;
        while (bytes-- > 0)
        {
            length <<= 8;
            length += this._readDERByte ();
            org.webpki.asn1._lengthCheck (length);
        }
    }
    this.start_of_body = this.position;
    this.body = new Uint8Array (length);
    for (var i = 0; i < length; i++)
    {
        this.body[i] = this._readDERByte (); 
    }
    if (this.tag == org.webpki.asn1.TAGS.SEQUENCE || this.tag == org.webpki.asn1.TAGS.SET)
    {
        this.components = [];
        var new_der = this.body;
        while (new_der.length != 0)
        {
            var asn1_object = new org.webpki.asn1.ParsedASN1Object (new_der);
            var chunk = asn1_object.body.length + asn1_object.start_of_body; 
            this.components[this.components.length] = asn1_object;
            if (chunk > new_der.length)
            {
                org.webpki.asn1._error ("Length error for tag: " + asn1_object.tag);
            }
            new_der = new Uint8Array (new_der.subarray (chunk));
        }
    }
    if (this.tag != org.webpki.asn1.TAGS.NULL &&
        this.tag != org.webpki.asn1.TAGS.SEQUENCE &&
        this.tag != org.webpki.asn1.TAGS.SET)
    {
        if (this.body.length == 0)
        {
            org.webpki.asn1._error ("Zero-length body not permitted for tag: " + this.tag);
        }
    }
    return this;
};

/* int */org.webpki.asn1.ParsedASN1Object.prototype._readDERByte = function ()
{
    if (this.position >= this.raw_der.length)
    {
        org.webpki.asn1._error ("Buffer underrun for tag: " + this.tag);
    }
    return this.raw_der[this.position++];
};

/* int */org.webpki.asn1.ParsedASN1Object.prototype.numberOfComponents = function ()
{
    if (this.components === undefined)
    {
        org.webpki.asn1._error ("This object type doesn't have components: " + this.tag);
    }
    return this.components.length;
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1Object.prototype.getComponent = function (index)
{
    if (index >= this.numberOfComponents ())
    {
        org.webpki.asn1._error ("Component index out of range: " + index);
    }
    return this.components[index];
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.getASN1ObjectIDRawData = function ()
{
    return this._getBodyData (org.webpki.asn1.TAGS.OID);
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.getASN1Integer = function ()
{
    return this._getBodyData (org.webpki.asn1.TAGS.INTEGER);
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.getASN1PositiveInteger = function ()
{
    var data = this.getASN1Integer ();
    if (data[0] > 127)
    {
        org.webpki.asn1._error ("Unexpected negative integer value");
    }
    return data;
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.getASN1BitString = function (/* boolean */unused_must_be_zero)
{
    var raw = this._getBodyData (org.webpki.asn1.TAGS.BITSTRING);
    if (unused_must_be_zero)
    {
        if (raw[0] != 0)
        {
            org.webpki.asn1._error ("Bitstring with unused bits not allowed");
        }
        raw = new Uint8Array (raw.subarray (1));
    }
    return raw;
};

/* void */org.webpki.asn1.ParsedASN1Object.prototype.getASN1NULL = function ()
{
    if (this._getBodyData (org.webpki.asn1.TAGS.NULL).length != 0)
    {
        org.webpki.asn1._error ("Misformed ASN.1 NULL");
    }
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1Object.prototype.getASN1Sequence = function ()
{
    this._getBodyData (org.webpki.asn1.TAGS.SEQUENCE);
    return this;
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1Object.prototype.getASN1Set = function ()
{
    this._getBodyData (org.webpki.asn1.TAGS.SET);
    return this;
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype._getBodyData = function (/* int */tag, /* boolean */optional_accept_zero)
{
    if (tag != this.tag)
    {
        org.webpki.asn1._error ("Tag mismatch, expected: " + tag + " got: " + this.tag);
    }
    return this.body;
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.getBodyData = function ()
{
    return this._getBodyData (this.tag);
};

/* int */org.webpki.asn1.ParsedASN1Object.prototype.getTag = function ()
{
    return this.tag;
};

/* Uint8Array */org.webpki.asn1.ParsedASN1Object.prototype.encode = function ()
{
    return new Uint8Array (this.raw_der.subarray (0, this.body.length + this.start_of_body));
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1Sequence = function (/* Uint8Array */raw_der)
{
    var sequence = new org.webpki.asn1.ParsedASN1Object (raw_der, org.webpki.asn1.TAGS.SEQUENCE);
    if (sequence.body.length != (raw_der.length - sequence.start_of_body))
    {
        org.webpki.asn1._error ("Sequence length error");
    }
    return sequence;
};
