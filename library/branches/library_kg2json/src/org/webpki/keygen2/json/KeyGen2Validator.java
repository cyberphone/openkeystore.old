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
package org.webpki.keygen2.json;

import java.io.IOException;

import java.net.URI;
import java.net.URISyntaxException;

import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONReaderHelper;

import org.webpki.sks.SecureKeyStore;

abstract class KeyGen2Validator extends JSONDecoder
  {
    JSONReaderHelper rd;
    
    String getKeyGen2ID (String name) throws IOException
      {
        return rd.getString (name);
      }
    
    String getKeyGen2URL (String name) throws IOException
      {
        String url = getKeyGen2URI (name);
        if (!url.matches ("https?://.*"))
          {
            bad ("Bad URL: " + url);
          }
        return url;
      }

    private void validateURI (String uri_string) throws IOException
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

    String getKeyGen2URI (String name) throws IOException
      {
        String uri = rd.getString (name);
        validateURI (uri);
        return uri;
      }

    short getKeyGen2PINLength (String name) throws IOException
      {
        int l = rd.getInt (name);
        if (l < 0 || l > SecureKeyStore.MAX_LENGTH_PIN_PUK)
          {
            bad ("Value out of range: " + l);
          }
        return (short) l;
      }

    void bad (String message) throws IOException
      {
        throw new IOException (message);
      }

    byte[] getKeyGen2MAC () throws IOException
      {
        byte[] mac = rd.getBinary (KeyGen2Constants.MAC_JSON);
        if (mac.length != 32)
          {
            bad ("MAC length error: " + mac.length);
          }
        return mac;
      }

    byte[] getKeyGen2EncryptedProtectionValue () throws IOException
      {
        byte[] encrypted_value = rd.getBinary (KeyGen2Constants.VALUE_JSON);
        if (encrypted_value.length < SecureKeyStore.AES_CBC_PKCS5_PADDING ||
            encrypted_value.length > SecureKeyStore.MAX_LENGTH_PIN_PUK + SecureKeyStore.AES_CBC_PKCS5_PADDING)
          {
            bad ("Encrypted protection value length error:" + encrypted_value.length);
          }
        return encrypted_value;
      }

    short getAuthorizationRetryLimit (int lower_limit) throws IOException
      {
        int retry_limit = rd.getInt (KeyGen2Constants.RETRY_LIMIT_JSON);
        if (retry_limit < lower_limit || retry_limit > 10000)
          {
            bad ("Retry limit range error: " + retry_limit);
          }
        return (short) retry_limit;
      }

    String[] getKeyGen2NonEmptyList (String name) throws IOException
      {
        String[] list = rd.getList (name);
        if (list.length == 0)
          {
            bad ("Empty list not allowed: " + name);
          }
        return list;
      }

    String[] getKeyGen2ListConditional (String name) throws IOException
      {
        if (rd.hasNext (name))
          {
            return getKeyGen2NonEmptyList (name);
          }
        return null;
      }

    String[] getKeyGen2URIList (String name) throws IOException
      {
        String[] uris = getKeyGen2NonEmptyList (name);
        for (String uri : uris)
          {
            validateURI (uri);
          }
        return uris;
      }
  }
