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

import java.util.Date;
import java.util.Vector;

import org.webpki.util.ISODateTime;

/**
 * For writing array elements.
 */
public class JSONArrayWriter implements Serializable
  {
    private static final long serialVersionUID = 1L;

    Vector<JSONValue> array;
    
    public JSONArrayWriter ()
      {
        array = new Vector<JSONValue> ();
      }

    JSONArrayWriter (Vector<JSONValue> array)
      {
        this.array = array;
      }

    JSONArrayWriter add (JSONTypes type, Object value) throws IOException
      {
        array.add (new JSONValue (type, value));
        return this;
      }

    public JSONArrayWriter setString (String value) throws IOException
      {
        return add (JSONTypes.STRING, value);
      }

    public JSONArrayWriter setInt (int value) throws IOException
      {
        return add (JSONTypes.INTEGER, Integer.toString (value));
      }

    public JSONArrayWriter setLong (long value) throws IOException
      {
        return add (JSONTypes.INTEGER, Long.toString (value));
      }

    public JSONArrayWriter setBigDecimal (BigDecimal value) throws IOException
      {
        return add (JSONTypes.INTEGER, value.toString ());
      }

    public JSONArrayWriter setBigInteger (BigInteger value) throws IOException
      {
        return add (JSONTypes.INTEGER, value.toString ());
      }

    public JSONArrayWriter setDouble (double value) throws IOException
      {
        return add (JSONTypes.DOUBLE, Double.toString (value));
      }

    public JSONArrayWriter setBoolean (boolean value) throws IOException
      {
        return add (JSONTypes.BOOLEAN, Boolean.toString (value));
      }

    public JSONArrayWriter setNULL () throws IOException
      {
        return add (JSONTypes.NULL, "null");
      }

    public JSONArrayWriter setDateTime (Date date_time) throws IOException
      {
        return setString (ISODateTime.formatDateTime (date_time));
      }

    public JSONArrayWriter setArray () throws IOException
      {
        Vector<JSONValue> new_array = new Vector<JSONValue> ();
        add (JSONTypes.ARRAY, new_array);
        return new JSONArrayWriter (new_array);
      }

    public JSONObjectWriter setObject () throws IOException
      {
        JSONObject holder = new JSONObject ();
        add (JSONTypes.OBJECT, holder);
        return new JSONObjectWriter (holder);
      }

    public byte[] serializeJSONArray (JSONOutputFormats output_format) throws IOException
      {
        JSONObject dummy = new JSONObject ();
        dummy.properties.put (null, new JSONValue (JSONTypes.ARRAY, array));
        return new JSONObjectWriter (dummy).serializeJSONObject (output_format);
      }
  }
