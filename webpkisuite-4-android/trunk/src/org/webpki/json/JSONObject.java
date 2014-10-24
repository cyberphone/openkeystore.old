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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Vector;

/**
 * Local support class for holding JSON objects.
 */
class JSONObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    LinkedHashMap<String, JSONValue> properties = new LinkedHashMap<String, JSONValue> ();

    HashSet<String> read_flag = new HashSet<String> ();
    
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

    @SuppressWarnings("unchecked")
    static void checkForUnread (JSONObject json_object) throws IOException
      {
        for (String name : json_object.properties.keySet ())
          {
            JSONValue value = json_object.properties.get (name);
            if (!json_object.read_flag.contains (name))
              {
                throw new IOException ("Property \"" + name + "\" was never read");
              }
            if (value.type == JSONTypes.OBJECT)
              {
                checkForUnread ((JSONObject)value.value);
              }
            else if (value.type == JSONTypes.ARRAY)
              {
                for (JSONValue object : (Vector<JSONValue>)value.value)
                  {
                    if (object.type == JSONTypes.OBJECT)
                      {
                        checkForUnread ((JSONObject)object.value);
                      }
                  }
              }
          }
       }
    }
