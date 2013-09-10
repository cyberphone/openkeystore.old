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

import java.util.Vector;

/**
 * For writing array elements.
 */
public class JSONArrayWriter
  {
    Vector<JSONValue> array;

    JSONArrayWriter (Vector<JSONValue> array)
      {
        this.array = array;
      }

    void add (JSONTypes type, Object value) throws IOException
      {
        if (!array.isEmpty () && array.firstElement ().type != type)
          {
            throw new IOException ("Mixed types for arrays: " + type + " versus " + array.firstElement ().type);
          }
        array.add (new JSONValue (type, value));
      }

    public JSONArrayWriter setString (String value) throws IOException
      {
        add (JSONTypes.STRING, value);
        return this;
      }

    public JSONArrayWriter setInt (int value) throws IOException
      {
        add (JSONTypes.INTEGER, String.valueOf (value));
        return this;
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
  }
