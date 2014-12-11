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
import java.util.LinkedHashMap;
import java.util.Vector;

/**
 * Local support class for holding JSON objects.
 * Note that outer-level arrays are (&quot;hackishly&quot;) represented as a 
 * JSON object having a single <code>null</code> property.
 */
class JSONObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    LinkedHashMap<String, JSONValue> properties = new LinkedHashMap<String, JSONValue> ();

    JSONObject ()
      {
      }

    void setProperty (String name, JSONValue value) throws IOException
      {
        if (name.length () == 0)
          {
            throw new IOException ("Empty property names not allowed");
          }
        if (properties.put (name, value) != null)
          {
            throw new IOException ("Duplicate property: " + name);
          }
      }

    static void checkObjectForUnread (JSONObject json_object) throws IOException
      {
        for (String name : json_object.properties.keySet ())
          {
            JSONValue value = json_object.properties.get (name);
            if (value == null) // See JSONSignatureDecoder...
              {
                continue;
              }
            if (!value.read_flag)
              {
                throw new IOException ("Property \"" + name + "\" was never read");
              }
            if (value.type == JSONTypes.OBJECT)
              {
                checkObjectForUnread ((JSONObject)value.value);
              }
            else if (value.type == JSONTypes.ARRAY)
              {
                checkArrayForUnread (value, name);
              }
          }
       }

    @SuppressWarnings("unchecked")
    static void checkArrayForUnread (JSONValue array, String name) throws IOException
      {
        for (JSONValue array_element : (Vector<JSONValue>)array.value)
          {
            if (array_element.type == JSONTypes.OBJECT)
              {
                checkObjectForUnread ((JSONObject)array_element.value);
              }
            else if (array_element.type == JSONTypes.ARRAY)
              {
                checkArrayForUnread (array_element, name);
              }
            else if (!array_element.read_flag)
              {
                throw new IOException ("Value \"" + (String)array_element.value + "\" of array \"" + name + "\" was never read");
              }
          }
      }
  }
