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

    private final static char[] MODIFIED_BASE64 = {
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

    
    private Base64URL ()
      {
      }
    
      ////////////////////
     ////   DECODE   //// Throws IOException if argument isn't base64URL
    ////////////////////

    private static byte[] decode (byte[] encoded) throws IOException
      {
        byte[] semidecoded = new byte[encoded.length];
        for (int i = 0; i < encoded.length; i++)
          {
            switch (encoded[i])
              {
                case (byte)'A': semidecoded[i] = 0; break;
                case (byte)'B': semidecoded[i] = 1; break;
                case (byte)'C': semidecoded[i] = 2; break;
                case (byte)'D': semidecoded[i] = 3; break;
                case (byte)'E': semidecoded[i] = 4; break;
                case (byte)'F': semidecoded[i] = 5; break;
                case (byte)'G': semidecoded[i] = 6; break;
                case (byte)'H': semidecoded[i] = 7; break;
                case (byte)'I': semidecoded[i] = 8; break;
                case (byte)'J': semidecoded[i] = 9; break;
                case (byte)'K': semidecoded[i] = 10; break;
                case (byte)'L': semidecoded[i] = 11; break;
                case (byte)'M': semidecoded[i] = 12; break;
                case (byte)'N': semidecoded[i] = 13; break;
                case (byte)'O': semidecoded[i] = 14; break;
                case (byte)'P': semidecoded[i] = 15; break;
                case (byte)'Q': semidecoded[i] = 16; break;
                case (byte)'R': semidecoded[i] = 17; break;
                case (byte)'S': semidecoded[i] = 18; break;
                case (byte)'T': semidecoded[i] = 19; break;
                case (byte)'U': semidecoded[i] = 20; break;
                case (byte)'V': semidecoded[i] = 21; break;
                case (byte)'W': semidecoded[i] = 22; break;
                case (byte)'X': semidecoded[i] = 23; break;
                case (byte)'Y': semidecoded[i] = 24; break;
                case (byte)'Z': semidecoded[i] = 25; break;
                case (byte)'a': semidecoded[i] = 26; break;
                case (byte)'b': semidecoded[i] = 27; break;
                case (byte)'c': semidecoded[i] = 28; break;
                case (byte)'d': semidecoded[i] = 29; break;
                case (byte)'e': semidecoded[i] = 30; break;
                case (byte)'f': semidecoded[i] = 31; break;
                case (byte)'g': semidecoded[i] = 32; break;
                case (byte)'h': semidecoded[i] = 33; break;
                case (byte)'i': semidecoded[i] = 34; break;
                case (byte)'j': semidecoded[i] = 35; break;
                case (byte)'k': semidecoded[i] = 36; break;
                case (byte)'l': semidecoded[i] = 37; break;
                case (byte)'m': semidecoded[i] = 38; break;
                case (byte)'n': semidecoded[i] = 39; break;
                case (byte)'o': semidecoded[i] = 40; break;
                case (byte)'p': semidecoded[i] = 41; break;
                case (byte)'q': semidecoded[i] = 42; break;
                case (byte)'r': semidecoded[i] = 43; break;
                case (byte)'s': semidecoded[i] = 44; break;
                case (byte)'t': semidecoded[i] = 45; break;
                case (byte)'u': semidecoded[i] = 46; break;
                case (byte)'v': semidecoded[i] = 47; break;
                case (byte)'w': semidecoded[i] = 48; break;
                case (byte)'x': semidecoded[i] = 49; break;
                case (byte)'y': semidecoded[i] = 50; break;
                case (byte)'z': semidecoded[i] = 51; break;
                case (byte)'0': semidecoded[i] = 52; break;
                case (byte)'1': semidecoded[i] = 53; break;
                case (byte)'2': semidecoded[i] = 54; break;
                case (byte)'3': semidecoded[i] = 55; break;
                case (byte)'4': semidecoded[i] = 56; break;
                case (byte)'5': semidecoded[i] = 57; break;
                case (byte)'6': semidecoded[i] = 58; break;
                case (byte)'7': semidecoded[i] = 59; break;
                case (byte)'8': semidecoded[i] = 60; break;
                case (byte)'9': semidecoded[i] = 61; break;
                case (byte)'-': semidecoded[i] = 62; break;
                case (byte)'_': semidecoded[i] = 63; break;
                default: throw new IOException("Not valid Base64URL data (bad byte at index " + i);
              }
          }
        byte[] decoded;
        if (encoded.length % 4 != 0) decoded = new byte[(encoded.length / 4) * 3 + (encoded.length % 4) - 1];
        else decoded = new byte[(encoded.length / 4) * 3];
        
        // -----:  D E C O D E :-----
        int i = 0, j = 0;
        //decode in groups of four bytes
        while(j < decoded.length - (decoded.length % 3))
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j++] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            decoded[j++] = (byte)((semidecoded[i++] << 6) | semidecoded[i++]);
          }
        //decode "odd" bytes
        if(decoded.length % 3 == 1)
          {
            decoded[j] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
          }
        else if (decoded.length % 3 == 2)
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
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
    public static byte[] getBinaryFromBase64URL (String base64url) throws IOException
      {
        return decode (base64url.getBytes ("UTF-8"));
      }
    
      ////////////////////
     ////   ENCODE   //// Does not throw exceptions
    ////////////////////

    private static byte[] encode (byte[] uncoded)
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
            encoded[i++] = (byte)(MODIFIED_BASE64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(MODIFIED_BASE64[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0xf)]);
            encoded[i++] = (byte)(MODIFIED_BASE64[((uncoded[j++] << 2) & 0x3c) | ((uncoded[j] >>> 6) & 0x3)]);
            encoded[i++] = (byte)(MODIFIED_BASE64[uncoded[j++] & 0x3F]);
          }
        //encode  "odd" bytes
        if (modulo3 == 1)
          {
            encoded[i++] = (byte)(MODIFIED_BASE64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(MODIFIED_BASE64[(uncoded[j] << 4) & 0x30]);
          }
        else if (modulo3 == 2)
          {
            encoded[i++] = (byte)(MODIFIED_BASE64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(MODIFIED_BASE64[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0xf)]);
            encoded[i++] = (byte)(MODIFIED_BASE64[(uncoded[j] << 2) & 0x3c]);
          }
        //return results
        return encoded;
    }
    
    
    /** [Encoding] Converts a binary byte array to a base64url encoded String.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param binary_blob uncoded data
     * @return encoded data as a String
     */
    public static String getBase64URLFromBinary (byte[] binary_blob)
      {
        try
          {
            return new String (encode (binary_blob), "UTF-8");
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
            buffer.append (MODIFIED_BASE64[random[i] & 0x3F]);
          }
        return buffer.toString ();
      }
  }
