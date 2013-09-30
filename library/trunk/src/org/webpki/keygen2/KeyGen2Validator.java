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
package org.webpki.keygen2;

import java.io.IOException;

import java.math.BigInteger;

import java.net.URI;

import java.net.URISyntaxException;

import java.util.GregorianCalendar;
import java.util.Vector;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;

import org.webpki.sks.SecureKeyStore;

abstract class KeyGen2Validator extends JSONDecoder
  {
    static String getID (JSONObjectReader rd, String name) throws IOException
      {
        return rd.getString (name);
      }
    
    static String getURL (JSONObjectReader rd, String name) throws IOException
      {
        String url = getURI (rd, name);
        if (!url.matches ("https?://.*"))
          {
            bad ("Bad URL: " + url);
          }
        return url;
      }

    static private void validateURI (String uri_string) throws IOException
      {
        try
          {
            URI uri = new URI (uri_string);
            if (!uri.isAbsolute ())
              {
                bad ("Bad URI: " + uri);
              }
          }
        catch (URISyntaxException e)
          {
            throw new IOException (e);
          }
      }

    static String getURI (JSONObjectReader rd, String name) throws IOException
      {
        String uri = rd.getString (name);
        validateURI (uri);
        return uri;
      }

    static short getPINLength (JSONObjectReader rd, String name) throws IOException
      {
        int l = rd.getInt (name);
        if (l < 0 || l > SecureKeyStore.MAX_LENGTH_PIN_PUK)
          {
            bad ("Value out of range: " + l);
          }
        return (short) l;
      }

    static void bad (String message) throws IOException
      {
        throw new IOException (message);
      }

    static byte[] getMAC (JSONObjectReader rd) throws IOException
      {
        byte[] mac = rd.getBinary (KeyGen2Constants.MAC_JSON);
        if (mac.length != 32)
          {
            bad ("MAC length error: " + mac.length);
          }
        return mac;
      }

    static byte[] getEncryptedProtectionValue (JSONObjectReader rd) throws IOException
      {
        byte[] encrypted_value = rd.getBinary (KeyGen2Constants.VALUE_JSON);
        if (encrypted_value.length < SecureKeyStore.AES_CBC_PKCS5_PADDING ||
            encrypted_value.length > SecureKeyStore.MAX_LENGTH_PIN_PUK + SecureKeyStore.AES_CBC_PKCS5_PADDING)
          {
            bad ("Encrypted protection value length error:" + encrypted_value.length);
          }
        return encrypted_value;
      }

    static short getAuthorizationRetryLimit (JSONObjectReader rd, int lower_limit) throws IOException
      {
        int retry_limit = rd.getInt (KeyGen2Constants.RETRY_LIMIT_JSON);
        if (retry_limit < lower_limit || retry_limit > 10000)
          {
            bad ("Retry limit range error: " + retry_limit);
          }
        return (short) retry_limit;
      }

    static String[] getNonEmptyList (JSONObjectReader rd, String name) throws IOException
      {
        String[] list = rd.getStringArray (name);
        if (list.length == 0)
          {
            bad ("Empty list not allowed: " + name);
          }
        return list;
      }

    static String[] getListConditional (JSONObjectReader rd, String name) throws IOException
      {
        return rd.hasProperty (name) ? getNonEmptyList (rd, name) : null;
      }

    static String[] getURIList (JSONObjectReader rd, String name) throws IOException
      {
        String[] uris = getNonEmptyList (rd, name);
        for (String uri : uris)
          {
            validateURI (uri);
          }
        return uris;
      }

    static String[] getURIListConditional (JSONObjectReader rd, String name) throws IOException
      {
        return rd.hasProperty (name) ? getURIList (rd, name) : null;
      }

    static BigInteger getBigIntegerConditional (JSONObjectReader rd, String name) throws IOException
      {
        return rd.hasProperty (name) ? rd.getBigInteger (name) : null;
      }

    static GregorianCalendar getDateTimeConditional (JSONObjectReader rd, String name) throws IOException
      {
        return rd.hasProperty (name) ? rd.getDateTime (name) : null;
      }

    static Vector<JSONObjectReader> getObjectArrayConditional (JSONObjectReader rd, String name) throws IOException
      {
        Vector<JSONObjectReader> result = new Vector<JSONObjectReader> ();
        if (rd.hasProperty (name))
          {
            JSONArrayReader arr = rd.getArray (name);
            while (arr.hasMore ())
              {
                result.add (arr.getObject ());
             }
          }
        return result;
      }

    @Override
    final protected String getContext ()
      {
        return KeyGen2Constants.KEYGEN2_NS;
      }
  }
