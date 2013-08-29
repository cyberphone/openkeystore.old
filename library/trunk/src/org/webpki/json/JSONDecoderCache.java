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

import java.util.Hashtable;
import java.util.Vector;

import org.webpki.util.ArrayUtil;

/**
 * Stores {@link JSONDecoder} classes for automatic instantiation during parsing.
 * This is (sort of) an emulation of XML schema caches.
 * <p>
 * The cache system assumes that JSON documents follow a strict convention:<br>
 * &nbsp;<br>
 * <code>&nbsp;&nbsp;{<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&quot;</code><i>MessageName</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;@jmns&quot;:&nbsp;&quot;</code><i>Namespace</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.&nbsp;&nbsp;&nbsp;</code><i>Arbitrary JSON Payload</i><code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>
 * &nbsp;&nbsp;}</code><br>
 * 
 */
public class JSONDecoderCache
  {
    /**
     * JMNS = JSON Message Name Space
     */
    public static final String JMNS_JSON = "@jmns";
    
    boolean test_unread = true;
    
    static class RegisteredJSONDecoder
      {
        String jmns, root_property;
        
        RegisteredJSONDecoder (String jmns, String root_property)
          {
            this.jmns = jmns;
            this.root_property = root_property;
          }
        
        public int hashCode ()
          {
            return jmns.hashCode () ^ root_property.hashCode ();
          }
        
        public boolean equals (Object o)
          {
            return o instanceof RegisteredJSONDecoder &&
                   jmns.equals (((RegisteredJSONDecoder)o).jmns) &&
                   root_property.equals (((RegisteredJSONDecoder)o).root_property);
          }
      }

    Hashtable<RegisteredJSONDecoder,Class<? extends JSONDecoder>> class_map = new Hashtable<RegisteredJSONDecoder,Class<? extends JSONDecoder>> ();
    
    public JSONDecoder parse (byte[] json_utf8) throws IOException
      {
        JSONParser parser = new JSONParser ();
        JSONObject root = parser.parse (json_utf8);
        if (root.properties.size () != 1)
          {
            throw new IOException ("Expected a single property, got: " + root.properties.size ());
          }
        String root_property = root.properties.keySet ().iterator ().next ();
        JSONValue value = root.properties.get (root_property);
        if (!(value.value instanceof JSONObject))
          {
            throw new IOException ("Expected an object as message body");
          }
        JSONReaderHelper reader = new JSONReaderHelper ((JSONObject)value.value);
        reader.root = root;
        String jmns = reader.getString (JMNS_JSON);
        Class<? extends JSONDecoder> decoder_class = class_map.get (new RegisteredJSONDecoder (jmns, root_property));
        if (decoder_class == null)
          {
            throw new IOException ("Unknown JSONDecoder type: " + root_property + ", " + jmns);
          }
        try
          {
            JSONDecoder decoder = decoder_class.newInstance ();
            decoder.root = root;
            decoder.unmarshallJSONData (reader);
            if (test_unread)
              {
                checkForUnread (reader.current, root_property);
              }
            return decoder;
          }
        catch (InstantiationException e)
          {
            throw new IOException (e);
          }
        catch (IllegalAccessException e)
          {
            throw new IOException (e);
          }
      }

    @SuppressWarnings("unchecked")
    void checkForUnread (JSONObject json_object, String property) throws IOException
      {
        if (json_object.reader.hasNext ())
          {
            throw new IOException ("Property \"" + json_object.reader.next () + "\" of \"" + property + "\" wasn't read");
          }
        for (String name : json_object.properties.keySet ())
          {
            JSONValue value = json_object.properties.get (name);
            if (value.type == JSONTypes.OBJECT)
              {
                checkForUnread ((JSONObject)value.value, name);
              }
            else if (value.type == JSONTypes.ARRAY)
              {
                for (JSONValue object : (Vector<JSONValue>)value.value)
                  {
                    if (object.type == JSONTypes.OBJECT)
                      {
                        checkForUnread ((JSONObject)object.value, name);
                      }
                  }
              }
          }
      }

    public void addToCache (Class<? extends JSONDecoder> json_decoder) throws IOException
      {
        try
          {
            JSONDecoder decoder = json_decoder.newInstance ();
            class_map.put (new RegisteredJSONDecoder (decoder.getJMNS (), decoder.getRootProperty ()), decoder.getClass ());
          }
        catch (InstantiationException ie)
          {
            throw new IOException ("Class " + json_decoder.getName () + " is not a valid JSONDecoder", ie);
          }
        catch (IllegalAccessException iae)
          {
            throw new IOException ("Class " + json_decoder.getName () + " is not a valid JSONDecoder", iae);
          }
      }

    public void addToCache (String json_decoder_path) throws IOException
      {
        try
          {
            addToCache (Class.forName (json_decoder_path).asSubclass (JSONDecoder.class));
          }
        catch (ClassNotFoundException cnfe)
          {
            throw new IOException ("Class " + json_decoder_path + " can't be found", cnfe);
          }
      }

    public static void main (String[] argc)
      {
        if (argc.length != 3)
          {
            System.out.println ("\nclass-name instance-document test-unread");
            System.exit (0);
          }
        try
          {
            JSONDecoderCache parser = new JSONDecoderCache ();
            parser.setCheckForUnreadProperties (new Boolean(argc[2]));
            parser.addToCache (argc[0]);
            JSONDecoder doc = parser.parse (ArrayUtil.readFile (argc[1]));
            System.out.print (new String (JSONWriter.serializeParsedJSONDocument (doc), "UTF-8"));
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }

    public void setCheckForUnreadProperties (boolean flag)
      {
        test_unread = flag;
      }
  }
