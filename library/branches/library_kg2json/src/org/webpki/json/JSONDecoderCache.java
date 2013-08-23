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
 * Parses JSON into a DOM-like tree.
 */
public class JSONDecoderCache
  {
    public static final String VERSION_JSON = "Version";
    
    JSONWriter.JSONHolder root;
    
    boolean test_unread = true;
    
    static class MessageTypes
      {
        String version, root_property;
        
        MessageTypes (String version, String root_property)
          {
            this.version = version;
            this.root_property = root_property;
          }
        
        public int hashCode ()
          {
            return version.hashCode () ^ root_property.hashCode ();
          }
        
        public boolean equals (Object o)
          {
            return o instanceof MessageTypes &&
                   version.equals (((MessageTypes)o).version) &&
                   root_property.equals (((MessageTypes)o).root_property);
          }
      }

    Hashtable<MessageTypes,Class<? extends JSONDecoder>> class_map = new Hashtable<MessageTypes,Class<? extends JSONDecoder>> ();
    
    public JSONDecoder parse (byte[] json_utf8) throws IOException
      {
        JSONParser parser = new JSONParser ();
        parser.parse (json_utf8);
        root = parser.root;
        if (root.properties.size () != 1)
          {
            throw new IOException ("Expected a single property, got: " + root.properties.size ());
          }
        String root_property = root.properties.keySet ().iterator ().next ();
        JSONWriter.JSONValue value = root.properties.get (root_property);
        if (!(value.value instanceof JSONWriter.JSONHolder))
          {
            throw new IOException ("Expected an object as message body");
          }
        JSONReaderHelper reader = new JSONReaderHelper ((JSONWriter.JSONHolder)value.value);
        String version = reader.getString (VERSION_JSON);
        Class<? extends JSONDecoder> decoder_class = class_map.get (new MessageTypes (version, root_property));
        if (decoder_class == null)
          {
            throw new IOException ("Unknown JSONDecoder type: " + root_property + ", " + version);
          }
        try
          {
            JSONDecoder decoder = (JSONDecoder)decoder_class.newInstance ();
            decoder.unmarshallJSONData (reader);
            if (test_unread)
              {
                checkForUnread (reader.root, root_property);
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

    void checkForUnread (JSONWriter.JSONHolder json_object, String property) throws IOException
      {
        if (json_object.reader.hasNext ())
          {
            throw new IOException ("Property \"" + json_object.reader.next () + "\" of \"" + property + "\" wasn't read");
          }
        for (String name : json_object.properties.keySet ())
          {
            JSONWriter.JSONValue value = json_object.properties.get (name);
            if (!value.simple)
              {
                if (value.value instanceof JSONWriter.JSONHolder)
                  {
                    checkForUnread ((JSONWriter.JSONHolder)value.value, name);
                  }
                else
                  {
                    Vector<Object> array = (Vector<Object>)value.value;
                    for (Object object : array)
                      {
                        if (object instanceof JSONWriter.JSONHolder)
                          {
                            checkForUnread ((JSONWriter.JSONHolder)object, name);
                          }
                      }
                  }
              }
          }
      }

    public void addToCache (Class<? extends JSONDecoder> message_type) throws IOException
      {
        try
          {
            JSONDecoder decoder = message_type.newInstance ();
            class_map.put (new MessageTypes (decoder.getVersion (), decoder.getRootProperty ()), decoder.getClass ());
          }
        catch (InstantiationException ie)
          {
            throw new IOException ("Class " + message_type.getName () + " is not a valid JSONDecoder");
          }
        catch (IllegalAccessException iae)
          {
            throw new IOException ("Class " + message_type.getName () + " is not a valid JSONDecoder");
          }
      }

    public void addToCache (String message_type) throws IOException
      {
        try
          {
            addToCache (Class.forName (message_type).asSubclass (JSONDecoder.class));
          }
        catch (ClassNotFoundException cnfe)
          {
            throw new IOException ("Class " + message_type + " can't be found");
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
            parser.setCheckForUnread (new Boolean(argc[2]));
            parser.addToCache (argc[0]);
            parser.parse (ArrayUtil.readFile (argc[1]));
            System.out.print (new String (new JSONWriter (parser.root).serializeJSONStructure (), "UTF-8"));
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }

    public void setCheckForUnread (boolean flag)
      {
        test_unread = flag;
      }
  }
