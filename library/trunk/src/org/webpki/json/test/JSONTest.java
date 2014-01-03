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
package org.webpki.json.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.util.Date;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONTypes;

import org.webpki.util.ArrayUtil;

/**
 * JSON JUnit suite
 */
public class JSONTest
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
    
    @BeforeClass
    public static void openFile () throws Exception
      {
        CustomCryptoProvider.forcedLoad ();
      }

    @SuppressWarnings("serial")
    public static class Reader extends JSONDecoder
      {
        void test (boolean ok) throws IOException
          {
            if (!ok) throw new IOException ("Bad");
          }

        @Override
        protected void readJSONData (JSONObjectReader rd) throws IOException
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
        public String getContext ()
          {
             return CONTEXT;
          }
      }

    @SuppressWarnings("serial")
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
        public String getContext ()
          {
            return CONTEXT;
          }
      }
    
    @SuppressWarnings("serial")
    public static class ESC extends JSONDecoder
      {
        String escape;
        
        @Override
        protected void readJSONData (JSONObjectReader rd) throws IOException
          {
            escape = rd.getString ("Esca\npe");
          }
  
        @Override
        public String getContext ()
          {
            return "http://example.com/escape";
          }

        @Override
        public String getQualifier ()
          {
            return "Escaper";
          }
      }

    enum PARSER_ERR 
      {
        MISS_ARG    ("Missing argument"),
        ARRAY_LIMIT ("Trying to read past of array limit: "),
        EXPECTED    ("Expected '"),
        SYNTAX      ("Undecodable argument");
        
        String mess;
        PARSER_ERR (String mess)
          {
            this.mess = mess;
          }
      }

    PARSER_ERR expected_error;
    
    void checkException (IOException e)
      {
        if (expected_error == null)
          {
            fail (e.getMessage ());
          }
        String error = e.getMessage ();
        if (error.length () > expected_error.mess.length ())
          {
            error = error.substring (0, expected_error.mess.length ());
          }
        if (!expected_error.mess.equals (error))
          {
            fail ("Wrong error: " + e.getMessage ());
          }
      }
    
    void checkException (Exception e, String compare_message)
      {
        String m = e.getMessage ();
        if (m == null || !m.equals (compare_message))
          {
            fail ("Exception: " + m);
          }
      }

    void booleanValues (boolean value) throws IOException
      {
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setBoolean (value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getBoolean () == value);
        or = new JSONObjectWriter ();
        or.setBoolean ("name", value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBoolean ("name") == value);
      }

    void dateTime (Date value) throws IOException
      {
        value = new Date ((value.getTime () / 1000) * 1000);
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setDateTime (value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getDateTime ().getTime ().equals (value));
        or = new JSONObjectWriter ();
        or.setDateTime ("name", value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getDateTime("name").getTime ().equals (value));
      }

    void bigIntegerValues (BigInteger value) throws IOException
      {
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setBigInteger (value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getBigInteger ().equals (value));
        or = new JSONObjectWriter ();
        or.setBigInteger ("name", value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBigInteger("name").equals (value));
      }

    void bigDecimalValues (BigDecimal value) throws IOException
      {
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setBigDecimal (value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getBigDecimal ().equals (value));
        or = new JSONObjectWriter ();
        or.setBigDecimal ("name", value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBigDecimal("name").equals (value));
      }

    void longVariables (long value) throws IOException
      {
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setLong (value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getLong () == value);
        or = new JSONObjectWriter ();
        or.setLong ("name", value);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getLong ("name") == value);
      }

    void badArgument (String string)
      {
        try
          {
            simpleObjectType (string);
            fail ("Didn't bomb");
            simpleArrayType (string);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
      }

    void floatingPoint (String string, double ref) throws Exception
      {
        assertTrue (simpleArrayType  (string).getDouble () == ref);
        assertTrue (simpleObjectType (string).getDouble ("name") == ref);
        assertTrue (simpleArrayType  (string).getElementType () == JSONTypes.DOUBLE);
        assertTrue (simpleObjectType (string).getPropertyType ("name") == JSONTypes.DOUBLE);
        assertTrue (simpleArrayType  (string + "  ").getElementType () == JSONTypes.DOUBLE);
        assertTrue (simpleObjectType (string + "  ").getPropertyType ("name") == JSONTypes.DOUBLE);
        JSONObjectWriter or = new JSONObjectWriter ();
        or.setArray ("name").setDouble (ref);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getDouble () == ref);
        or = new JSONObjectWriter ().setDouble ("name", ref);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getDouble ("name") == ref);
      }

    JSONObjectReader simpleObjectType (String string) throws IOException
      {
        return JSONParser.parse (new StringBuffer ("{\"name\":")
                                  .append (string)
                                  .append ('}').toString ());
      }

    JSONArrayReader simpleArrayType (String string) throws IOException
      {
        return JSONParser.parse (new StringBuffer ("{\"name\":[")
                                   .append (string)
                                   .append ("]}").toString ()).getArray ("name");
      }
    
    static final String ESCAPING = "{ \"@context\" : \"http://example.com/escape\", " +
                                     "\"@qualifier\" : \"Escaper\", " +
                                     "\"Esca\\npe\":\"\\u0041\\u000A\\tTAB\\nNL /\\\\\\\"\" }";
    static final String ESCAPING2 = "{ \"@context\" : \"http://example.com/escape\", " +
                                    "\"Esca\\npe\":\"\\u0041\\u000A\\tTAB\\nNL /\\\\\\\"\" }";
    @Test
    public void DocumentCache () throws Exception
      {
        JSONDecoderCache cache = new JSONDecoderCache ();        
        cache.addToCache (Reader.class);
        cache.addToCache (ESC.class);
        try
          {
            cache.parse (ESCAPING2.getBytes ("UTF-8"));
            fail ("Should have failed");
          }
        catch (Exception e)
          {
            checkException (e, "Unknown JSONDecoder type: http://example.com/escape");
          }
        ESC escape = (ESC) cache.parse (ESCAPING.getBytes ("UTF-8"));
        assertTrue ("Escaping", escape.escape.equals ("A\n\tTAB\nNL /\\\""));
        byte[] data = new Writer ().serializeJSONDocument (JSONOutputFormats.PRETTY_PRINT);
        Reader reader = (Reader) cache.parse (data);
        byte[] output = JSONObjectWriter.serializeParsedJSONDocument (reader, JSONOutputFormats.PRETTY_PRINT);
        assertTrue (ArrayUtil.compare (data, output));
      }

    @Test
    public void ParserPrimitives () throws Exception
      {
        JSONArrayReader ar; 
        JSONObjectReader or; 
        assertTrue (simpleArrayType   ("10  ").getInt () == 10);
        assertTrue (simpleObjectType  ("10  ").getInt ("name") == 10);
        assertTrue (simpleArrayType   ("4").getInt () == 4);
        assertTrue (simpleObjectType  ("4").getInt ("name") == 4);
        assertTrue (simpleArrayType   ("40000000000000000").getBigInteger ().equals (new BigInteger ("40000000000000000")));
        assertTrue (simpleObjectType  ("40000000000000000").getBigInteger ("name").equals (new BigInteger ("40000000000000000")));
        assertTrue (simpleArrayType   ("40000000000000000").getBigDecimal ().equals (new BigDecimal ("40000000000000000")));
        assertTrue (simpleObjectType  ("40000000000000000").getBigDecimal ("name").equals (new BigDecimal ("40000000000000000")));
        assertTrue (simpleArrayType   ("40000000000000000.45").getBigDecimal ().equals (new BigDecimal ("40000000000000000.45")));
        assertTrue (simpleObjectType  ("40000000000000000.45").getBigDecimal ("name").equals (new BigDecimal ("40000000000000000.45")));
        assertTrue (simpleArrayType   ("0.0").getBigDecimal ().equals (new BigDecimal ("0.0")));
        assertTrue (simpleObjectType  ("0.0").getBigDecimal ("name").equals (new BigDecimal ("0.0")));
        assertTrue (simpleArrayType   ("40000000000000000").getDouble () == new Double ("40000000000000000"));
        assertTrue (simpleObjectType  ("40000000000000000").getDouble ("name") == new Double ("40000000000000000"));
        assertTrue (simpleArrayType   ("40000000000000000.45").getDouble () == 40000000000000000.45);
        assertTrue (simpleObjectType  ("40000000000000000.45").getDouble ("name") == 40000000000000000.45);
        assertTrue (simpleArrayType   ("40.45e10").getDouble () == 40.45e10);
        assertTrue (simpleObjectType  ("40.45e10").getDouble ("name") == 40.45e10);
        assertTrue (simpleArrayType   ("   true   ").getBoolean ());
        assertTrue (simpleArrayType   ("true").getBoolean ());
        assertTrue (simpleObjectType  ("true").getBoolean ("name"));
        assertFalse (simpleArrayType  ("false").getBoolean ());
        assertFalse (simpleObjectType ("false").getBoolean ("name"));
        assertTrue (simpleArrayType   ("null").getIfNULL ());
        assertTrue (simpleObjectType  ("null").getIfNULL ("name"));
        assertFalse ((or = simpleObjectType ("3")).getIfNULL ("name"));
        assertTrue (or.getInt ("name") == 3);
        assertFalse ((ar = simpleArrayType ("3")).getIfNULL ());
        assertTrue (ar.getInt () == 3);
        assertTrue ((ar = simpleArrayType ("null")).getIfNULL ());
        expected_error = PARSER_ERR.ARRAY_LIMIT;
        try
          {
            assertTrue (ar.getInt () == 3);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        expected_error = PARSER_ERR.MISS_ARG;
        try
          {
            assertTrue (simpleArrayType (",0").getInt () == 0);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        try
          {
            assertTrue (simpleArrayType ("0,").getInt () == 0);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        try
          {
            assertTrue (simpleObjectType ("").getInt ("name") == 0);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        expected_error = PARSER_ERR.ARRAY_LIMIT;
        try
          {
            assertTrue (simpleArrayType ("").getInt () == 0);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        assertTrue ((ar = simpleArrayType ("4")).getInt () == 4);
        try
          {
            assertTrue (ar.getInt () == 0);
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e);
          }
        expected_error = PARSER_ERR.SYNTAX;
        badArgument ("-");
        badArgument (".");
        badArgument ("e-3");
        badArgument ("flase");
        expected_error = PARSER_ERR.EXPECTED;
        badArgument ("1.0 e4");
        floatingPoint ("1.0e4", 1.0e4);
        floatingPoint ("0.9999e-99", 0.9999e-99);
        floatingPoint ("1.0E+4", 10000);
        floatingPoint (     "1.0e4"    , 1.0e4);
        floatingPoint ("-0.0", -0.0);
        floatingPoint ("+0.0", +0.0);
        floatingPoint ("+1", +1);
        floatingPoint ("-0", -0);
        floatingPoint (".1", .1);
        floatingPoint ("1.", 1.0);
        floatingPoint ("01", 01);
        longVariables (1235454234343434l);
        longVariables (0xa885abafaba0l);
        bigDecimalValues (new BigDecimal ("3232323243243234234243234234243243243243243234243"));
        bigDecimalValues (new BigDecimal ("323232324324.3234234243234234243243243243243234243"));
        bigIntegerValues (new BigInteger ("3232323243243234234243234234243243243243243234243"));
        dateTime (new Date ());
        booleanValues (true);
        booleanValues (false);
      }

    @Test
    public void OuterArrays () throws Exception
      {
        JSONArrayWriter aw = new JSONArrayWriter ();
        aw.setString ("hi,there");
        aw.setObject ().setBoolean ("Boolish", true).setInt ("intish", -567);
        JSONObjectReader or = JSONParser.parse (aw.serializeJSONArray (JSONOutputFormats.PRETTY_PRINT));
        JSONArrayReader ar = or.getJSONArrayReader ();
        assertTrue (ar.getString ().equals ("hi,there"));
        or = ar.getObject ();
        assertFalse (ar.hasMore ());
        assertTrue (or.getBoolean ("Boolish"));
        assertTrue (or.getInt ("intish") == -567);

        try
          {
            aw = new JSONArrayWriter ();
            aw.setString ("hi,there");
            or = JSONParser.parse (aw.serializeJSONArray (JSONOutputFormats.PRETTY_PRINT));
            new JSONObjectWriter (or);
            fail ("Should have failed");
          }
        catch (Exception e)
          {
            checkException (e, "You cannot update array objects");
          }
      }
  }
