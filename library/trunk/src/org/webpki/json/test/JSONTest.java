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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.spec.X509EncodedKeySpec;

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
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONTypes;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

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
        CustomCryptoProvider.forcedLoad (true);
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
        or.setArray ("name").setDateTime (value, false);
        assertTrue (JSONParser.parse (or.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("name").getDateTime ().getTime ().equals (value));
        or = new JSONObjectWriter ();
        or.setDateTime ("name", value, false);
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

    JSONObjectReader simpleObjectType2  (String string) throws IOException
      {
        return simpleObjectType ('"' + string + '"');
      }

    JSONArrayReader simpleArrayType (String string) throws IOException
      {
        return JSONParser.parse (new StringBuffer ("{\"name\":[")
                                   .append (string)
                                   .append ("]}").toString ()).getArray ("name");
      }
    
    JSONArrayReader simpleArrayType2 (String string) throws IOException
      {
        return simpleArrayType ('"' + string + '"');
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
        assertTrue  (simpleArrayType   ("10  ").getInt () == 10);
        assertTrue  (simpleObjectType  ("10  ").getInt ("name") == 10);
        assertTrue  (simpleArrayType   ("4").getInt () == 4);
        assertTrue  (simpleObjectType  ("4").getInt ("name") == 4);
        assertTrue  (simpleArrayType2  ("40000000000000000").getBigInteger ().equals (new BigInteger ("40000000000000000")));
        assertTrue  (simpleObjectType2 ("40000000000000000").getBigInteger ("name").equals (new BigInteger ("40000000000000000")));
        assertTrue  (simpleArrayType2  ("40000000000000000").getBigDecimal ().equals (new BigDecimal ("40000000000000000")));
        assertTrue  (simpleObjectType2 ("40000000000000000").getBigDecimal ("name").equals (new BigDecimal ("40000000000000000")));
        assertTrue  (simpleArrayType2  ("40000000000000000.45").getBigDecimal ().equals (new BigDecimal ("40000000000000000.45")));
        assertTrue  (simpleObjectType2 ("40000000000000000.45").getBigDecimal ("name").equals (new BigDecimal ("40000000000000000.45")));
        assertTrue  (simpleArrayType2  ("0.0").getBigDecimal ().equals (new BigDecimal ("0.0")));
        assertTrue  (simpleObjectType2 ("0.0").getBigDecimal ("name").equals (new BigDecimal ("0.0")));
        assertTrue  (simpleArrayType   ("40000000000000000").getDouble () == new Double ("40000000000000000"));
        assertTrue  (simpleObjectType  ("40000000000000000").getDouble ("name") == new Double ("40000000000000000"));
        assertTrue  (simpleArrayType   ("40000000000000000.45").getDouble () == 40000000000000000.45);
        assertTrue  (simpleObjectType  ("40000000000000000.45").getDouble ("name") == 40000000000000000.45);
        assertTrue  (simpleArrayType   ("40.45e10").getDouble () == 40.45e10);
        assertTrue  (simpleObjectType  ("40.45e10").getDouble ("name") == 40.45e10);
        assertTrue  (simpleArrayType   ("   true   ").getBoolean ());
        assertTrue  (simpleArrayType   ("true").getBoolean ());
        assertTrue  (simpleObjectType  ("true").getBoolean ("name"));
        assertFalse (simpleArrayType   ("false").getBoolean ());
        assertFalse (simpleObjectType  ("false").getBoolean ("name"));
        assertTrue  (simpleArrayType   ("null").getIfNULL ());
        assertTrue  (simpleObjectType  ("null").getIfNULL ("name"));
        or = simpleObjectType ("3");
        assertFalse (or.getIfNULL ("name"));
        assertTrue (or.getInt ("name") == 3);
        ar = simpleArrayType ("3");
        assertFalse (ar.getIfNULL ());
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
        blobValues ();
        simpleArrays ();
      }

    private void simpleArrays () throws Exception
      {
        JSONObjectWriter ow = new JSONObjectWriter ();
        ow.setArray ("arr").setString ("f").setBoolean (false);
        JSONObjectReader or = JSONParser.parse (ow.serializeJSONObject (JSONOutputFormats.NORMALIZED));
        try
          {
            or.getStringArray ("arr");
            fail ("Didn't bomb");
          }
        catch (IOException e)
          {
            checkException (e, "Incompatible types, expected: STRING actual: BOOLEAN");
          }
        ow = new JSONObjectWriter ();
        ow.setArray ("arr").setString ("f").setString ("hgh");
        or = JSONParser.parse (ow.serializeJSONObject (JSONOutputFormats.NORMALIZED));
        assertTrue (or.getStringArray ("arr").length == 2);
      }

    private void blobValues () throws IOException
      {
        for (int times = 0; times < 1000; times++)
          {
              for (int i = 0; i < 10; i++)
              {
                  byte[] iarr = new byte[i];
                  for (int j = 0; j < i; j++)
                  {
                      iarr[j] = (byte) Math.floor(Math.random()*256);
                  }
                  byte[] arr = JSONParser.parse (new JSONObjectWriter ().setBinary ("blob", iarr).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
                  assertTrue ("Length",arr.length == iarr.length);
                  for (int q = 0; q < arr.length; q++)
                  {
                      assertTrue ("Content", arr[q] == iarr[q]);
                  }
                  JSONObjectWriter ow = new JSONObjectWriter ();
                  ow.setArray ("arr").setBinary (iarr);
                  arr = JSONParser.parse (ow.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getArray ("arr").getBinary ();
                  assertTrue ("Length",arr.length == iarr.length);
                  for (int q = 0; q < arr.length; q++)
                  {
                      assertTrue ("Content", arr[q] == iarr[q]);
                  }
              }
          }
        boolean should_fail = true;
        try
          {
            JSONParser.parse (new JSONObjectWriter ().setString ("blob", "a").serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
            should_fail = false;
          }
        catch (IOException e)
          {
          }
        assertTrue ("a", should_fail);
        should_fail = true;
        try
          {
            JSONParser.parse (new JSONObjectWriter ().setString ("blob", "+xdFdYg").serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
            should_fail = false;
          }
        catch (IOException e)
          {
          }
        assertTrue ("+xdFdYg", should_fail);
        should_fail = true;
        try
          {
            JSONParser.parse (new JSONObjectWriter ().setString ("blob", "/xdFdYg").serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
            should_fail = false;
          }
        catch (IOException e)
          {
          }
        assertTrue ("/xdFdYg", should_fail);
        // We are pretty strict, yes...
        for (int i = 0; i < 64; i++)
          {
            try
              {
                String string = "A" + org.webpki.util.Base64URL.BASE64URL[i]; 
                should_fail = i % 16 > 0;
                JSONParser.parse (new JSONObjectWriter ().setString ("blob", string).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
              }
            catch (IOException e)
              {
                should_fail = !should_fail;
              }
            assertFalse ("A", should_fail);
            try
              {
                String string = "AA" + org.webpki.util.Base64URL.BASE64URL[i]; 
                should_fail = i % 4 > 0;
                JSONParser.parse (new JSONObjectWriter ().setString ("blob", string).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getBinary ("blob");
              }
            catch (IOException e)
              {
                  should_fail = !should_fail;
              }
            assertFalse ("AA", should_fail);
          }
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

    @Test
    public void UnreadProperties () throws Exception
      {
        JSONObjectWriter ow = new JSONObjectWriter ();
        ow.setInt ("intv", 3);
        ow.setInt ("intb", 3);
        JSONObjectReader or = JSONParser.parse (ow.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT));
        try
          {
            or.getInt ("intb");
            or.checkForUnread ();
            fail ("Should have failed");
          }
        catch (Exception e)
          {
            checkException (e, "Property \"intv\" was never read");
          }
      }
    
    static final String p521_jcs =
      "{" +
      "  \"PublicKey\": " +
      "     {" +
      "      \"EC\":" + 
      "        {" +
      "          \"NamedCurve\": \"http://xmlns.webpki.org/sks/algorithm#ec.nist.p521\"," +
      "          \"X\": \"AQggHPZ-De2Tq_7U7v8ADpjyouKk6eV97Lujt9NdIcZgWI_cyOLv9HZulGWtC7I3X73ABE-rx95hAKbxiqQ1q0bA\"," +
      "          \"Y\": \"AP5yYckNtHGuzZ9Gb8oqueBXwgG5Riu5LnbhQUz5Mb_Xjo4mnhqe1f396ldZMUvyJdi2O03OZdhkpVv_ks2CsYHp\"" +
      "        }" +
      "    }" +
      "}";

    static final String p521_jcs_xml =
      "{" +
      "  \"PublicKey\": " +
      "     {" +
      "      \"EC\":" + 
      "        {" +
      "          \"NamedCurve\": \"urn:oid:1.3.132.0.35\"," +
      "          \"X\": \"AQggHPZ-De2Tq_7U7v8ADpjyouKk6eV97Lujt9NdIcZgWI_cyOLv9HZulGWtC7I3X73ABE-rx95hAKbxiqQ1q0bA\"," +
      "          \"Y\": \"AP5yYckNtHGuzZ9Gb8oqueBXwgG5Riu5LnbhQUz5Mb_Xjo4mnhqe1f396ldZMUvyJdi2O03OZdhkpVv_ks2CsYHp\"" +
      "        }" +
      "    }" +
      "}";

    static final String p521_spki =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCCAc9n4N7ZOr_tTu_wAOmPKi4qTp5X3su6O3010hxmBYj9zI4u" +
        "_0dm6UZa0LsjdfvcAET6vH3mEApvGKpDWrRsAA_nJhyQ20ca7Nn0Zvyiq54FfCAblGK7kuduFBTPkxv9eOjiae" +
        "Gp7V_f3qV1kxS_Il2LY7Tc5l2GSlW_-SzYKxgek";
      
    static final String rsa_jcs =
      "{" +
      "  \"PublicKey\":" + 
      "    {" +
      "      \"RSA\":" + 
      "        {" +
      "          \"Modulus\": \"tMzneIjQz_C5fptrerKudR4H4LuoAek0HbH4xnKDMvbUbzYYlrfuORkVcvKKPYl5odONGr61d0G3YW3Pvf" +
"snMwabXH4flk5Akf21Xd1GnAy-FCZoyiORHLfSLcjs2MDPbEWbol3U70PJl3OpyG81yE4lrRXd816JqRLMBFoJXMDIPYtwqa0cEfcLVIHhI" +
"-ktsId5WpIW-AAwYftQITGn1CarwjtVZ3_g8mlfW_G4xC43D_5LVNPQM3R7TnAP3IQ1wyntT29dpvc8_aaxOlmhwg1xhFc3smDv1R4mOo-M" +
"Eel_TjKDaci5xsRC0VuzOp5HKyjHKHOBCF3BFcGHV_zo9Q\"," +
      "          \"Exponent\": \"AQAB\"" + 
      "        }" + 
      "    }" + 
      "}";

    static final String rsa_spki =
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtMzneIjQz_C5fptrerKudR4H4LuoAek0HbH4xnKDMvbUbzYYlrfuORkVcvKKPYl5" +
"odONGr61d0G3YW3PvfsnMwabXH4flk5Akf21Xd1GnAy-FCZoyiORHLfSLcjs2MDPbEWbol3U70PJl3OpyG81yE4lrRXd816JqRLMBFoJXMDI" +
"PYtwqa0cEfcLVIHhI-ktsId5WpIW-AAwYftQITGn1CarwjtVZ3_g8mlfW_G4xC43D_5LVNPQM3R7TnAP3IQ1wyntT29dpvc8_aaxOlmhwg1x" +
"hFc3smDv1R4mOo-MEel_TjKDaci5xsRC0VuzOp5HKyjHKHOBCF3BFcGHV_zo9QIDAQAB";

    static final String p256_jcs =
      "{" +
      "  \"PublicKey\":" + 
      "    {" +
      "      \"EC\":" + 
      "        {" +
      "          \"NamedCurve\": \"http://xmlns.webpki.org/sks/algorithm#ec.nist.p256\"," +
      "          \"X\": \"GRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2SxHkDiOU\"," +
      "          \"Y\": \"isxpqxSx6AAEmZfgL5HevS67ejfm_4HcsB883TUaccs\"" +
      "        }" +
      "    }" +
      "}";


    static final String p256_spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_HsBvHR9235X7zF2Sx" +
                                    "HkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw";

    PublicKey getPublicKeyFromSPKI (byte[] spki) throws Exception
      {
        try
          {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec (spki));
          }
        catch (GeneralSecurityException e)
          {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec (spki));
          }
      }
        
    void serializeKey (String spki, String jcs) throws Exception
      {
        byte[] spki_bin = Base64URL.decode (spki);
        JSONObjectReader or = JSONParser.parse (jcs);
        PublicKey public_key = or.getPublicKey ();
        assertTrue ("Public key", ArrayUtil.compare (public_key.getEncoded (), spki_bin));
        JSONObjectWriter ow = new JSONObjectWriter ().setXMLDSigECCurveOption (jcs.indexOf ("urn:oid") > 0);
        assertTrue ("Public key jcs",
             ArrayUtil.compare (ow.setPublicKey (getPublicKeyFromSPKI (spki_bin)).serializeJSONObject (JSONOutputFormats.NORMALIZED),
                                new JSONObjectWriter (or).serializeJSONObject (JSONOutputFormats.NORMALIZED)));
        JSONObjectReader pub_key_object = or.getObject (JSONSignatureDecoder.PUBLIC_KEY_JSON);
        boolean rsa_flag = pub_key_object.hasProperty (JSONSignatureDecoder.RSA_JSON);
        pub_key_object = pub_key_object.getObject (rsa_flag ? JSONSignatureDecoder.RSA_JSON : JSONSignatureDecoder.EC_JSON);
        String key_parm = rsa_flag ? JSONSignatureDecoder.MODULUS_JSON : JSONSignatureDecoder.Y_JSON;
        byte[] parm_bytes = pub_key_object.getBinary (key_parm);
        boolean must_fail = true;
        if (rsa_flag)
          {
            parm_bytes = ArrayUtil.add (new byte[]{0}, parm_bytes);
          }
        else if (parm_bytes[0] == 0)
          {
            byte[] pb_new = new byte[parm_bytes.length - 1];
            for (int i = 0; i < pb_new.length; i++)
              {
                pb_new[i] = parm_bytes[i + 1];
              }
            parm_bytes = pb_new;
          }
        else
          {
            must_fail = false;
          }
        JSONObjectWriter updated_pub_key_object = new JSONObjectWriter (pub_key_object);
        updated_pub_key_object.setupForRewrite (key_parm);
        updated_pub_key_object.setBinary (key_parm, parm_bytes);
        try
          {
            JSONParser.parse (new JSONObjectWriter (or).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)).getPublicKey ();
            assertFalse ("Should have failed", must_fail);
          }
        catch (Exception e)
          {
            assertTrue ("Shouldn't have failed", must_fail);
            checkException (e, rsa_flag ? 
                "Public RSA key parameter \"" + JSONSignatureDecoder.MODULUS_JSON + "\" contains leading zeroes" 
                                        :
                "Public EC key parameter \"" + JSONSignatureDecoder.Y_JSON + "\" is not nomalized");
          }
      }

    @Test
    public void KeySerializing () throws Exception
      {
        serializeKey (p256_spki, p256_jcs);
        serializeKey (p521_spki, p521_jcs);
        serializeKey (p521_spki, p521_jcs_xml);
        serializeKey (rsa_spki, rsa_jcs);
      }

    @Test
    public void ObjectInclusion () throws Exception
      {
        JSONObjectWriter ow = new JSONObjectWriter ();
        ow.setString ("Yes", "No");
        JSONObjectWriter ow2 = ow.setObject ("Yay");
        JSONArrayWriter aw = ow2.setArray ("Arr");
        aw.setInt (2);
        aw.setString ("Blah");
        byte[] json = ow.serializeJSONObject (JSONOutputFormats.NORMALIZED);
        ow = new JSONObjectWriter ();
        ow.setString ("Yes", "No");
        ow2 = new JSONObjectWriter ();
        aw = ow2.setArray ("Arr");
        aw.setInt (2);
        aw.setString ("Blah");
        assertTrue ("Writer added", ArrayUtil.compare (json, ow.setObject ("Yay", ow2).serializeJSONObject (JSONOutputFormats.NORMALIZED)));
        JSONObjectReader or = JSONParser.parse (json).getObject ("Yay");
        ow = new JSONObjectWriter ();
        ow.setString ("Yes", "No");
        assertTrue ("Reader added", ArrayUtil.compare (json, ow.setObject ("Yay", or).serializeJSONObject (JSONOutputFormats.NORMALIZED)));
      }
  }
