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
package org.webpki.json.test;

import java.io.IOException;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONReaderHelper;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;

/**
 * Testing public keys
 */
public class Test
  {
    static final String CONTEXT = "http://example.com/test";
    
    static final String BOOL_TRUE = "boolTrue";
    static final String BOOL_FALSE = "boolFalse";
    static final String BOOL_UNKNOWM = "boolUnknown";

    static final String STRING = "string";
    static final String STRING_VALUE = "Hi!";
    static final String STRING_UNKNOWM = "nostring";

    static final String STRING_WITH_DEFAULT1 = "stringWithDefault1";
    static final String STRING_WITH_DEFAULT2 = "stringWithDefault2";
    static final String STRING_DEFAULT = "defstring";
    
    static final String BLOB = "blob";
    static final byte[] BLOB_VALUE = {0,1,2,3};
    
    static final String EMPTY_STRING_LIST = "esl";

    static final String STRING_LIST = "stringlist";
    static final String[] STRING_LIST_VALUE = {"one","two","three"};
    static final String SUPER_LONG_LINE = "jurtkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"; 

    static JSONDecoderCache cache = new JSONDecoderCache ();
    
    public static class Reader extends JSONDecoder
      {
        void test (boolean ok) throws IOException
          {
            if (!ok) throw new IOException ("Bad");
          }

        @Override
        protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
          {
            test (rd.getBoolean (BOOL_TRUE));
            test (!rd.getBoolean (BOOL_FALSE));
            test (!rd.getBooleanConditional (BOOL_UNKNOWM));
            test (!rd.getBooleanConditional (BOOL_UNKNOWM));
            test (rd.getString (STRING).equals (STRING_VALUE));
            test (rd.getStringConditional (STRING_UNKNOWM) == null);
            test (rd.getStringConditional (STRING_WITH_DEFAULT1, STRING_DEFAULT).equals (STRING_DEFAULT));
            test (rd.getStringConditional (STRING_WITH_DEFAULT2, STRING_DEFAULT).equals (STRING_VALUE));
            test (ArrayUtil.compare (rd.getBinary (BLOB), BLOB_VALUE));
            test (rd.getStringArray (EMPTY_STRING_LIST).length == 0);
            String[] list = rd.getStringArray (STRING_LIST);
            test (list.length == STRING_LIST_VALUE.length);
            for (int i = 0; i < list.length; i++)
              {
                test (list[i].equals (STRING_LIST_VALUE[i]));
              }
            test (rd.getArray ("KURT").getArray ().getString ().equals (SUPER_LONG_LINE));
            rd.getObject ("MURT").getString ("URK");
          }
  
        @Override
        protected String getContext ()
          {
             return CONTEXT;
          }
      }

    static class Writer extends JSONEncoder
      {
        @Override
        protected void writeJSONData (JSONObjectWriter wr) throws IOException
          {
            wr.setBoolean (BOOL_TRUE, true);
            wr.setBoolean (BOOL_FALSE, false);
            wr.setString (STRING, STRING_VALUE);
            wr.setString (STRING_WITH_DEFAULT2, STRING_VALUE);
            wr.setBinary (BLOB, BLOB_VALUE);
            wr.setStringArray (EMPTY_STRING_LIST, new String[0]);
            wr.setStringArray (STRING_LIST, STRING_LIST_VALUE);
            JSONArrayWriter aw = wr.setArray ("KURT");
            aw.setArray ().setString (SUPER_LONG_LINE).setString ("Ty");
            aw.setArray ().setString ("lurt").setString ("Ty");
            wr.setObject ("MURT").setString ("URK", "urk");
          }

        @Override
        protected String getContext ()
          {
            return CONTEXT;
          }
      }
    
    public static class ESC extends JSONDecoder
      {
        @Override
        protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
          {
            String escape = rd.getString ("Esca\npe");
            if (escape.equals ("A\n\tTAB\nNL /\\\""))
              {
                System.out.println ("Escape succeeded:\n" + ESCAPING);
              }
            else
              {
                throw new IOException ("Escape error: " + escape);
              }
          }
  
        @Override
        protected String getContext ()
          {
            return "http://example.com/escape";
          }

        @Override
        protected String getQualifier ()
          {
            return "Escaper";
          }
      }

    static final String ESCAPING = "{ \"@context\" : \"http://example.com/escape\", " +
                                     "\"@qualifier\" : \"Escaper\", " +
                                     "\"Esca\\npe\":\"\\u0041\\u000A\\tTAB\\nNL /\\\\\\\"\" }";

    public static void main (String[] argc)
      {
        try
          {
            cache.addToCache (Reader.class);
            cache.addToCache (ESC.class);
            byte[] data = new Writer ().serializeJSONDocument (JSONOutputFormats.PRETTY_PRINT);
            System.out.println (new String (data, "UTF-8"));
            Reader reader = (Reader) cache.parse (data);
            byte[] output = JSONObjectWriter.serializeParsedJSONDocument (reader, JSONOutputFormats.PRETTY_PRINT);
            if (ArrayUtil.compare (data, output))
              {
                System.out.println ("Input and output are equivalent");
              }
            cache.parse (ESCAPING.getBytes ("UTF-8"));
          }
        catch (Exception e)
          {
            e.printStackTrace ();
          }
      }
  }
