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
 * &nbsp;<br><code>
 * &nbsp;&nbsp;{<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;@context&quot;:&nbsp;&quot;</code><i>Message Context</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;@qualifier&quot;:&nbsp;&quot;</code><i>Message Type Qualifier</i><code>&quot;<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.&nbsp;&nbsp;&nbsp;</code><i>Arbitrary JSON Payload</i><code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.<br>
 * &nbsp;&nbsp;}</code><p>
 * Note: <code>@qualifier</code> is only required if multiple objects share the same <code>@context</code>.<p>
 * A restriction imposed by this particular JSON processing model is that all properties must by default be read.
 * 
 */
public class JSONDecoderCache
  {
    /**
     * Emulation of XML namespace
     */
    public static final String CONTEXT_JSON = "@context";
    
    /**
     * Emulation of XML top-level element. Optional
     */
    public static final String QUALIFIER_JSON = "@qualifier";
    
    static final char CONTEXT_QUALIFIER_DIVIDER = '$';

    boolean test_unread = true;
    
    Hashtable<String,Class<? extends JSONDecoder>> class_map = new Hashtable<String,Class<? extends JSONDecoder>> ();
    
    public JSONDecoder parse (byte[] json_utf8) throws IOException
      {
        JSONObjectReader reader = JSONParser.parse (json_utf8);
        String object_type_identifier = reader.getString (CONTEXT_JSON);
        if (reader.hasProperty (QUALIFIER_JSON))
          {
            object_type_identifier += CONTEXT_QUALIFIER_DIVIDER + reader.getString (QUALIFIER_JSON);
          }
        Class<? extends JSONDecoder> decoder_class = class_map.get (object_type_identifier);
        if (decoder_class == null)
          {
            throw new IOException ("Unknown JSONDecoder type: " + object_type_identifier);
          }
        try
          {
            JSONDecoder decoder = decoder_class.newInstance ();
            decoder.root = reader.json;
            decoder.unmarshallJSONData (reader);
            if (test_unread)
              {
                checkForUnread (reader.json);
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
    void checkForUnread (JSONObject json_object) throws IOException
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

    public void addToCache (Class<? extends JSONDecoder> json_decoder) throws IOException
      {
        try
          {
            JSONDecoder decoder = json_decoder.newInstance ();
            String object_type_identifier = decoder.getContext ();
            if (decoder.getQualifier () != null)
              {
                object_type_identifier += CONTEXT_QUALIFIER_DIVIDER + decoder.getQualifier ();
              }
            if (class_map.put (object_type_identifier, decoder.getClass ()) != null)
              {
                throw new IOException ("JSON document type already defined: " + object_type_identifier);
              }
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
        if (argc.length != 4)
          {
            System.out.println ("\nclass-name instance-document test-unread format(" + JSONOutputFormats.CANONICALIZED + "|" + JSONOutputFormats.PRETTY_JAVASCRIPT + "|" +  JSONOutputFormats.PRETTY_PRINT + ")");
            System.exit (0);
          }
        try
          {
            for (JSONOutputFormats of : JSONOutputFormats.values ())
              {
                if (of.toString ().equals (argc[3]))
                  {
                    JSONDecoderCache parser = new JSONDecoderCache ();
                    parser.setCheckForUnreadProperties (new Boolean(argc[2]));
                    parser.addToCache (argc[0]);
                    JSONDecoder doc = parser.parse (ArrayUtil.readFile (argc[1]));
                    System.out.print (new String (JSONObjectWriter.serializeParsedJSONDocument (doc, of), "UTF-8"));
                    return;
                  }
              }
            throw new IOException ("Unknown format: " + argc[3]);
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
