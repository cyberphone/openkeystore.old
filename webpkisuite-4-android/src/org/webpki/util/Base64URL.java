/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
package org.webpki.util;

import java.io.IOException;

import java.security.SecureRandom;

/**
 * Encodes/decodes base64URL data.
 * See RFC 4648 Table 2.
 */
public class Base64URL
  {
    
  ///////////////////////////////
 ////       ATTRIBUTES      ////
///////////////////////////////

    public final static char[] BASE64URL = {
    //   0   1   2   3   4   5   6   7
        'A','B','C','D','E','F','G','H', // 0
        'I','J','K','L','M','N','O','P', // 1
        'Q','R','S','T','U','V','W','X', // 2
        'Y','Z','a','b','c','d','e','f', // 3
        'g','h','i','j','k','l','m','n', // 4
        'o','p','q','r','s','t','u','v', // 5
        'w','x','y','z','0','1','2','3', // 6
        '4','5','6','7','8','9','-','_'  // 7
    };
    
    public final static byte[] DECODE_TABLE = {
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, 62, -1, -1,
        52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6, 
         7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51
    };


    
    private Base64URL ()
      {
      }
    
      ////////////////////
     ////   DECODE   //// Throws IOException if argument isn't base64URL
    ////////////////////

    private static byte[] decodeInternal (byte[] encoded) throws IOException
      {
        byte[] semidecoded = new byte[encoded.length];
        for (int i = 0; i < encoded.length; i++)
          {
            byte c = encoded[i];
            if (c < 0 || c >= DECODE_TABLE.length || (c = DECODE_TABLE[c]) < 0)
              {
                throw new IOException ("bad character at index " + i);
              }
            semidecoded[i] = c;
          }
        int decoded_length = (encoded.length / 4) * 3;
        int encoded_length_modulo_4 = encoded.length % 4; 
        if (encoded_length_modulo_4 != 0)
          {
             decoded_length += encoded_length_modulo_4 - 1;
          }
        byte[] decoded = new byte[decoded_length];
        int decoded_length_modulo_3 = decoded.length % 3;
        if (decoded_length_modulo_3 == 0 && encoded_length_modulo_4 != 0)
          {
              throw new IOException ("Wrong number of Base64URL characters");
          }
       
        // -----:  D E C O D E :-----
        int i = 0, j = 0;
        //decode in groups of four bytes
        while (j < decoded.length - decoded_length_modulo_3)
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j++] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            decoded[j++] = (byte)((semidecoded[i++] << 6) | semidecoded[i++]);
          }
        //decode "odd" bytes
        if (decoded_length_modulo_3 == 1)
          {
            decoded[j] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            if ((semidecoded[i] & 0x0F) != 0)
              {
                throw new IOException ("Wrong termination character");
              }
          }
        else if (decoded_length_modulo_3 == 2)
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            if ((semidecoded[i] & 0x03) != 0)
              {
                throw new IOException ("Wrong termination character");
              }
          }
        //return results
        return decoded;
      }
    
    /** [Decoding] Converts a base64url encoded String to a binary byte array.
     * For every 4 base64 bytes you'll get 3 binary bytes.
     * @param base64url encoded data
     * @return decoded data as a byte array
     * @exception IOException if the input data isn't valid base64 data
     * or if the input String contains characters
     * other than ASCII8.
     */
    public static byte[] decode (String base64url) throws IOException
      {
        return decodeInternal (base64url.getBytes ("UTF-8"));
      }
    
      ////////////////////
     ////   ENCODE   //// Does not throw exceptions
    ////////////////////

    private static byte[] encodeInternal (byte[] uncoded)
      {
        //determine length of output
        int i;
        int modulo3 = uncoded.length % 3;
        //(1)
        i = (uncoded.length / 3) * 4;
        //(2)
        if (modulo3 != 0)
          {
            i += modulo3 + 1;
          }
        //(3)
        byte[] encoded = new byte[i];
        i = 0;
        int j = 0;
        //encode by threes
        while (j < uncoded.length - modulo3)
          {
            encoded[i++] = (byte)(BASE64URL[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(BASE64URL[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0x0F)]);
            encoded[i++] = (byte)(BASE64URL[((uncoded[j++] << 2) & 0x3C) | ((uncoded[j] >>> 6) & 0x03)]);
            encoded[i++] = (byte)(BASE64URL[uncoded[j++] & 0x3F]);
          }
        //encode  "odd" bytes
        if (modulo3 == 1)
          {
            encoded[i++] = (byte)(BASE64URL[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(BASE64URL[(uncoded[j] << 4) & 0x30]);
          }
        else if (modulo3 == 2)
          {
            encoded[i++] = (byte)(BASE64URL[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(BASE64URL[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0x0F)]);
            encoded[i++] = (byte)(BASE64URL[(uncoded[j] << 2) & 0x3C]);
          }
        //return results
        return encoded;
    }
    
    
    /** [Encoding] Converts a binary byte array to a base64url encoded String.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param binary_blob uncoded data
     * @return encoded data as a String
     */
    public static String encode (byte[] binary_blob)
      {
        try
          {
            return new String (encodeInternal (binary_blob), "UTF-8");
          }
        catch (IOException e)
          {
            throw new RuntimeException (e);
          }
      }

    public static String generateURLFriendlyRandom (int length_in_characters)
      {
        byte[] random = new byte[length_in_characters];
        new SecureRandom ().nextBytes (random);
        StringBuffer buffer = new StringBuffer ();
        for (int i = 0; i < length_in_characters; i++)
          {
            buffer.append (BASE64URL[random[i] & 0x3F]);
          }
        return buffer.toString ();
      }
  }
