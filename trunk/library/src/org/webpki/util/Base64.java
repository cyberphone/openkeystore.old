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
package org.webpki.util;

import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Encodes/decodes base64 data.
 * @version 1.1 (2000-08-17)
 */
public class Base64
  {

    
  ///////////////////////////////
 ////       ATTRIBUTES      ////
///////////////////////////////

    private final static char[] aBase64 = {
    //   0   1   2   3   4   5   6   7
        'A','B','C','D','E','F','G','H', // 0
        'I','J','K','L','M','N','O','P', // 1
        'Q','R','S','T','U','V','W','X', // 2
        'Y','Z','a','b','c','d','e','f', // 3
        'g','h','i','j','k','l','m','n', // 4
        'o','p','q','r','s','t','u','v', // 5
        'w','x','y','z','0','1','2','3', // 6
        '4','5','6','7','8','9','+','/'  // 7
    };

    private static final int DEFAULT_CHARS_PER_ROW = 76; // 76/4*3 = 57 uncoded bytes
    private int encodedCharsPerRow;
    private boolean lineBreakOn;
    private boolean paddingOn;
    
  ///////////////////////////////
 ////   BEHAVIOUR SETTINGS  ////
///////////////////////////////
    
    /** Default constructor.<br>
     * <pre>
     * encodedCharsPerRow = 76; // 76/4*3 = 57 uncoded bytes
     * lineBreakOn = true;
     * paddingOn = true;
     * </pre>
     */
    public Base64 ()
      {
        encodedCharsPerRow = DEFAULT_CHARS_PER_ROW; // 76/4*3 = 57 uncoded bytes
        lineBreakOn = true;
        paddingOn = true;
      }
    
    /** Constructor.
     * @param linebreak whether or not the base64 encoded data should
     * be divided into several rows.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     */
    public Base64 (boolean linebreak)
      {
        encodedCharsPerRow = DEFAULT_CHARS_PER_ROW;
        lineBreakOn = linebreak;
        paddingOn = true;
      }
    
    /** Constructor.
     * @param encCharsARow number of encoded characters before each
     * linebreak.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     */
    public Base64 (int encCharsARow)
      {
        if (encCharsARow > 0)
          {
            encodedCharsPerRow = (encCharsARow/4)*4;
            if (encCharsARow%4 != 0) encodedCharsPerRow += 4;
            lineBreakOn = true;
          }
        else
          {
            encodedCharsPerRow = DEFAULT_CHARS_PER_ROW;
            lineBreakOn = false;
          }
        paddingOn = true;
      }
    
    /** Constructor.
     * @param encCharsARow number of encoded characters before each
     * linebreak.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     * @param padding whether or not the encoded base64 data should be padded at the end
     */
    public Base64 (int encCharsARow, boolean padding)
      {
        if (encCharsARow > 0)
          {
            encodedCharsPerRow = (encCharsARow/4)*4;
            if(encCharsARow%4 != 0) encodedCharsPerRow += 4;
            lineBreakOn = true;
          }
        else
          {
            encodedCharsPerRow = DEFAULT_CHARS_PER_ROW;
            lineBreakOn = false;
          }
        paddingOn = padding;
      }
    
    /** Resets all settings to their default values, as specified in
     * the default constructor
     */
    public void resetToDefault()
      {
        encodedCharsPerRow = DEFAULT_CHARS_PER_ROW;
        lineBreakOn = true;
        paddingOn = true;
      }
    
    /** Sets number of encoded characters before each linebreak.
     * If <code>count</code> isn't divisible by 4, it will be
     * treated as the nearest larger integer divisible by 4.
     * Must be larger than zero and no more than 76.
     * Default value is <code>76</code>.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     * @param count number of base64 characters in each row
     */
    public void setEncodedCharsPerRow (int count)
      {
        if (count > 0)
          {
            encodedCharsPerRow = (count/4)*4;
            if(count%4 != 0) encodedCharsPerRow += 4;
            //lineBreakOn = true;
          }
        else
          {
            encodedCharsPerRow = DEFAULT_CHARS_PER_ROW;
            lineBreakOn = false;
          }
      }
    
    /** If set to <code>true</code> the base64 encoded data will
     * be divided into a number of rows.
     * Default value is <code>true</code>.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     * @param on on/off switch for line break.
     */
    public void setLineBreakOn (boolean on)
      {
        lineBreakOn = on;
      }
    
    /** If set to <code>true</code> the base64 encoded data will
     * be padded at the end to make sure every 3 uncoded bytes
     * corresponds to 4 encoded ones. Max. 2 padding bytes.
     * Default value is <code>true</code>.
     * <b>Warning:</b> Deviating from default values, might cause compatibility
     * problems with other Base64 encoders/decoders.
     * @param on on/off switch for padding.
     */
    public void setPaddingOn (boolean on)
      {
        paddingOn = on;
      }
    
    
    /** Returns number of encoded characters before
     * each line feed.
     * @return number of base64 encoded characters per row
     */
    public int getEncodedCharsPerRow ()
      {
        return encodedCharsPerRow;
      }
    
    /** Tells you whether or not the base64 data will be
     * divided into a number of rows.
     * @return <code>true</code> if base64 data will include line feeds
     */
    public boolean getLineBreakOn ()
      {
        return lineBreakOn;
      }
    
    /** Tells you whether or not the base64 data will be padded
     * to preserve the 3:4 ratio between uncoded and encoded bytes.
     * @return <code>true</code> if base64 data will be padded
     */
    public boolean getPaddingOn ()
      {
        return paddingOn;
      }
    
  ///////////////////////////////////
 ////   CONVERTION METHODS      ////
///////////////////////////////////

    public static byte[] unicodeToByteArray (String unicode) throws IOException
      {
        return unicode.getBytes("UTF-8");
      }
    
    private static String byteArrayToUnicode(byte[] blob) throws IOException
      {
        String unicode = new String(blob, "UTF-8");
        //if there is data loss, the blob wasn't utf8 and the operation is aborted
        if (blob.length != unicode.getBytes("UTF-8").length) throw new IOException("Not valid Unicode data. Try using other method for decoding");
        return unicode;
      }
    
    public static byte[] stringToByteArray (String s) throws IOException
      {
        char[] temp = s.toCharArray();
        //take action on non ASCII8 characters
        int i = -1;
        byte[] results = new byte[temp.length];
        while (i < temp.length-1)
          {
            if ((temp[++i] & 0xFF00) == 0) results[i] = (byte)(temp[i] & 0x00FF); //only accept empty high bits
            else throw new IOException("Input String is not ASCII8. " +
                    "Unicode character (contains high order bits other than 0) at index " + i);
          }
        return results;
      }
    
    private static String byteArrayToString (byte[] blob)
      {
        char[] temp = new char[blob.length];
        for (int i = 0; i < blob.length; i++)
          {
            temp[i] = (char)(blob[i] & 0x00FF);
          }
        return String.valueOf(temp);
      }
    

    
  ////////////////////
 ////   DECODE   //// Throws IOException on error (if argument isn't base64)
////////////////////

    private byte[] decode(byte[] encoded) throws IOException
      {
        //removes all \r\n and padding chars from the data
        //and checks whether or not it's valid base64 data
        int j = encoded.length;
        while (j-- > 0)
            {
            if (encoded[j] > 32 && encoded[j] != '=') {
                break;
            }
            }
        
        int cnt = 0; int k = 0; int i = 0;
        byte[] semidecoded = new byte[encoded.length];
        //strip white space and determine validity of remaining bytes
        while(i <= j)
          {
            if (encoded[i] <= 32)
              {
            /* Ignore ws. */
                i++;
              }
            else
              {
                switch (encoded[i++])
                  {
                    case (byte)'A': semidecoded[k++] = 0; cnt++; break;
                    case (byte)'B': semidecoded[k++] = 1; cnt++; break;
                    case (byte)'C': semidecoded[k++] = 2; cnt++; break;
                    case (byte)'D': semidecoded[k++] = 3; cnt++; break;
                    case (byte)'E': semidecoded[k++] = 4; cnt++; break;
                    case (byte)'F': semidecoded[k++] = 5; cnt++; break;
                    case (byte)'G': semidecoded[k++] = 6; cnt++; break;
                    case (byte)'H': semidecoded[k++] = 7; cnt++; break;
                    case (byte)'I': semidecoded[k++] = 8; cnt++; break;
                    case (byte)'J': semidecoded[k++] = 9; cnt++; break;
                    case (byte)'K': semidecoded[k++] = 10; cnt++; break;
                    case (byte)'L': semidecoded[k++] = 11; cnt++; break;
                    case (byte)'M': semidecoded[k++] = 12; cnt++; break;
                    case (byte)'N': semidecoded[k++] = 13; cnt++; break;
                    case (byte)'O': semidecoded[k++] = 14; cnt++; break;
                    case (byte)'P': semidecoded[k++] = 15; cnt++; break;
                    case (byte)'Q': semidecoded[k++] = 16; cnt++; break;
                    case (byte)'R': semidecoded[k++] = 17; cnt++; break;
                    case (byte)'S': semidecoded[k++] = 18; cnt++; break;
                    case (byte)'T': semidecoded[k++] = 19; cnt++; break;
                    case (byte)'U': semidecoded[k++] = 20; cnt++; break;
                    case (byte)'V': semidecoded[k++] = 21; cnt++; break;
                    case (byte)'W': semidecoded[k++] = 22; cnt++; break;
                    case (byte)'X': semidecoded[k++] = 23; cnt++; break;
                    case (byte)'Y': semidecoded[k++] = 24; cnt++; break;
                    case (byte)'Z': semidecoded[k++] = 25; cnt++; break;
                    case (byte)'a': semidecoded[k++] = 26; cnt++; break;
                    case (byte)'b': semidecoded[k++] = 27; cnt++; break;
                    case (byte)'c': semidecoded[k++] = 28; cnt++; break;
                    case (byte)'d': semidecoded[k++] = 29; cnt++; break;
                    case (byte)'e': semidecoded[k++] = 30; cnt++; break;
                    case (byte)'f': semidecoded[k++] = 31; cnt++; break;
                    case (byte)'g': semidecoded[k++] = 32; cnt++; break;
                    case (byte)'h': semidecoded[k++] = 33; cnt++; break;
                    case (byte)'i': semidecoded[k++] = 34; cnt++; break;
                    case (byte)'j': semidecoded[k++] = 35; cnt++; break;
                    case (byte)'k': semidecoded[k++] = 36; cnt++; break;
                    case (byte)'l': semidecoded[k++] = 37; cnt++; break;
                    case (byte)'m': semidecoded[k++] = 38; cnt++; break;
                    case (byte)'n': semidecoded[k++] = 39; cnt++; break;
                    case (byte)'o': semidecoded[k++] = 40; cnt++; break;
                    case (byte)'p': semidecoded[k++] = 41; cnt++; break;
                    case (byte)'q': semidecoded[k++] = 42; cnt++; break;
                    case (byte)'r': semidecoded[k++] = 43; cnt++; break;
                    case (byte)'s': semidecoded[k++] = 44; cnt++; break;
                    case (byte)'t': semidecoded[k++] = 45; cnt++; break;
                    case (byte)'u': semidecoded[k++] = 46; cnt++; break;
                    case (byte)'v': semidecoded[k++] = 47; cnt++; break;
                    case (byte)'w': semidecoded[k++] = 48; cnt++; break;
                    case (byte)'x': semidecoded[k++] = 49; cnt++; break;
                    case (byte)'y': semidecoded[k++] = 50; cnt++; break;
                    case (byte)'z': semidecoded[k++] = 51; cnt++; break;
                    case (byte)'0': semidecoded[k++] = 52; cnt++; break;
                    case (byte)'1': semidecoded[k++] = 53; cnt++; break;
                    case (byte)'2': semidecoded[k++] = 54; cnt++; break;
                    case (byte)'3': semidecoded[k++] = 55; cnt++; break;
                    case (byte)'4': semidecoded[k++] = 56; cnt++; break;
                    case (byte)'5': semidecoded[k++] = 57; cnt++; break;
                    case (byte)'6': semidecoded[k++] = 58; cnt++; break;
                    case (byte)'7': semidecoded[k++] = 59; cnt++; break;
                    case (byte)'8': semidecoded[k++] = 60; cnt++; break;
                    case (byte)'9': semidecoded[k++] = 61; cnt++; break;
                    case (byte)'+': semidecoded[k++] = 62; cnt++; break;
                    case (byte)'/': semidecoded[k++] = 63; cnt++; break;
                    default: throw new IOException("Not valid Base64 data (bad byte at index " + (i-1) 
                                   + " : ascii value " + encoded[i - 1] + " )");
                  }
              }
          }
        //exclude padding byte (only last two chars)
        //this test is performed after the \r\n test to allow
        //a certain amount of white space in the input data
        //determine length of receiving byte array
        byte[] decoded;
        if (cnt%4 != 0) decoded = new byte[(cnt/4)*3+(cnt%4)-1];
        else decoded = new byte[(cnt/4)*3];
        
        // -----:  D E C O D E :-----
        i = 0; j = 0;
        //decode in groups of four bytes
        while(j < decoded.length - (decoded.length%3))
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j++] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            decoded[j++] = (byte)((semidecoded[i++] << 6) | semidecoded[i++]);
          }
        //decode "odd" bytes
        if(decoded.length%3 == 1)
          {
            decoded[j] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
          }
        else if (decoded.length%3 == 2)
          {
            decoded[j++] = (byte)((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j] = (byte)((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
          }
        //return results
        return decoded;
      }
    
    /** [Decoding] Converts a base64 encoded byte array to a binary byte array.
     * For every 4 base64 bytes you'll get 3 binary bytes.
     * @param base64_ascii8_blob encoded data
     * @return decoded data as a byte array
     * @exception IOException if the input data isn't valid base64 data
     */
    public byte[] getBinaryFromBase64Binary(byte[] base64_ascii8_blob) throws IOException
      {
        return decode(base64_ascii8_blob);
      }

    /** [Decoding] Converts a base64 encoded String to a binary byte array.
     * For every 4 base64 bytes you'll get 3 binary bytes.
     * @param base64 encoded data
     * @return decoded data as a byte array
     * @exception IOException if the input data isn't valid base64 data
     * or if the input String contains characters
     * other than ASCII8.
     */
    public byte[] getBinaryFromBase64String(String base64) throws IOException
      {
        return decode(stringToByteArray(base64));
      }
    
    /** [Decoding] Converts a base64 encoded byte array to a String representation of the binary data.
     * For every 4 base64 bytes you'll get 3 binary bytes.
     * @param base64_ascii8_blob encoded data
     * @return decoded data as a String
     * @exception IOException if the input data isn't valid base64 data.
     */
    public String getStringFromBase64Binary(byte[] base64_ascii8_blob) throws IOException
      {
        return byteArrayToString(decode(base64_ascii8_blob));
      }

    /** [Decoding] Converts a base64 encoded String to a String representation of the binary data.
     * For every 4 base64 bytes you'll get 3 binary bytes.
     * @param base64 encoded data
     * @return decoded data as a String
     * @exception IOException if the input data isn't valid base64 data
     * or if the input String contains characters
     * other than ASCII8.
     */
    public String getStringFromBase64String(String base64) throws IOException
      {
        return byteArrayToString(decode(stringToByteArray(base64)));
      }
    
    /** [Decoding] Converts a base64 encoded byte array to a Unicode String representation of the binary data (UTF-8).
     * For every 4 base64 bytes you'll get 3 binary bytes. Note, however, that these bytes are UTF-8 bytes
     * and is not equal to the length of the Unicode String.
     * @param base64_ascii8_blob encoded data
     * @return decoded data as a Unicode String
     * @exception IOException if the input data isn't valid base64 data
     * or if there is a problem converting UTF-8 to Unicode
     */
    public String getUnicodeFromBase64Binary(byte[] base64_ascii8_blob) throws IOException
      {
        return byteArrayToUnicode(decode(base64_ascii8_blob));
      }
    
    /** [Decoding] Converts a base64 encoded String to a Unicode String representation of the binary data (UTF-8).
     * For every 4 base64 bytes you'll get 3 binary bytes. Note, however, that these bytes are UTF-8 bytes
     * and is not equal to the length of the Unicode String.
     * @param base64 encoded data
     * @return decoded data as a Unicode String
     * @exception IOException if the input data isn't valid base64 data
     * or if there is a problem converting UTF-8 to Unicode
     */
    public String getUnicodeFromBase64String(String base64) throws IOException
      {
        return byteArrayToUnicode(decode(stringToByteArray(base64)));
      }


  ////////////////////
 ////   ENCODE   //// Should not cause errors
////////////////////

    private byte[] encode(byte[] uncoded)
      {
        //determine length of output
        int i;
        //(1)
        i = (uncoded.length/3)*4;
        //(2)
        if (uncoded.length%3 != 0)
          {
            if(paddingOn) i += 4;
            else i += uncoded.length%3 + 1;
          }
        //(3)
        if (lineBreakOn)
          {
            if (i%encodedCharsPerRow != 0) i += (i/encodedCharsPerRow)*2;
            else  i += ((i-1)/encodedCharsPerRow)*2; //don't end with line break
          }
        byte[] encoded = new byte[i];
        i = 0;
        int j = 0; int rowPos = 0;
        //encode by threes
        while (j < uncoded.length - uncoded.length%3)
          {
            encoded[i++] = (byte)(aBase64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(aBase64[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0xf)]);
            encoded[i++] = (byte)(aBase64[((uncoded[j++] << 2) & 0x3c) | ((uncoded[j] >>> 6) & 0x3)]);
            encoded[i++] = (byte)(aBase64[uncoded[j++] & 0x3F]);
            rowPos += 4;
            if (rowPos >= encodedCharsPerRow)
              {//linked to the positioning of (3)
                if (lineBreakOn && j != uncoded.length)
                  {//don't end with line break
                    encoded[i++] = (byte)'\r';
                    encoded[i++] = (byte)'\n';
                  }
                rowPos = 0;
              }
          }
        //encode  "odd" bytes
        if (uncoded.length%3 == 1)
          {
            encoded[i++] = (byte)(aBase64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(aBase64[(uncoded[j] << 4) & 0x30]);
            if (paddingOn)
              {
                encoded[i++] = (byte)'=';
                encoded[i] = (byte)'=';
              }
          }
        else if (uncoded.length%3 == 2)
          {
            encoded[i++] = (byte)(aBase64[(uncoded[j] >>> 2) & 0x3F]);
            encoded[i++] = (byte)(aBase64[((uncoded[j++] << 4) & 0x30) | ((uncoded[j] >>> 4) & 0xf)]);
            encoded[i++] = (byte)(aBase64[(uncoded[j] << 2) & 0x3c]);
            if(paddingOn) encoded[i] = (byte)'=';
          }
        //return results
        return encoded;
    }
    
    /** [Encoding] Converts a binary byte array to a base64 encoded byte array.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param binary_blob uncoded data
     * @return encoded data as a byte array
     */
    public byte[] getBase64BinaryFromBinary(byte[] binary_blob)
      {
        return encode(binary_blob);
      }

    /** [Encoding] Converts a String representation of a binary byte array to a base64 encoded byte array.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param ascii8 uncoded data
     * @return encoded data as a byte array
     * @exception IOException if the input
     * String contains non-ascii8 characters.
     */
    public byte[] getBase64BinaryFromString(String ascii8) throws IOException
      {
        //throws exception originally thrown from stringToByteArray()
        return encode(stringToByteArray(ascii8));
      }

    /** [Encoding] Converts a Unicode String representation of a binary byte array (UTF-8) to a base64 encoded byte array.
     * For every 3 binary bytes, you'll get 4 base64 bytes. Note, however, that these bytes are UTF-8 bytes
     * and is not equal to the length of the Unicode String.
     * @param unicode uncoded data
     * @return encoded data as a byte array
     * @exception IOException if there
     * is a problem converting Unicode to UTF-8.
     */
    public byte[] getBase64BinaryFromUnicode(String unicode) throws IOException
      {
        return encode(unicodeToByteArray(unicode));
      }
    
    /** [Encoding] Converts a binary byte array to a base64 encoded String.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param binary_blob uncoded data
     * @return encoded data as a String
     */
    public String getBase64StringFromBinary(byte[] binary_blob)
      {
        return byteArrayToString(encode(binary_blob));
      }

    /** [Encoding] Converts a String representation of a binary byte array to a base64 encoded String.
     * For every 3 binary bytes, you'll get 4 base64 bytes.
     * @param ascii8 uncoded data
     * @return encoded data as a String
     * @exception IOException if the input
     * String contains non-ascii8 characters.
     */
    public String getBase64StringFromString(String ascii8) throws IOException
      {
        //sends the call to other method
        //throws exception originally thrown from stringToByteArray()
        return byteArrayToString(encode(stringToByteArray(ascii8)));
      }
    
    /** [Encoding] Converts a Unicode String representation of a binary byte array (UTF-8) to a base64 encoded String.
     * For every 3 binary bytes, you'll get 4 base64 bytes. Note, however, that these bytes are UTF-8 bytes
     * and is not equal to the length of the Unicode String.
     * @param unicode uncoded data
     * @return encoded data as a String
     * @exception IOException if there
     * is a problem converting Unicode to UTF-8.
     */
    public String getBase64StringFromUnicode(String unicode) throws IOException
      {
        return byteArrayToString(encode(unicodeToByteArray(unicode)));
      }


  ///////////////////////////////
 ////       DEBUGGING       ////
///////////////////////////////
    
    
    final private static String COMMAND_LINE_USAGE = "\nUsage:\n\n  org.webpki.util.Base64 [e|d|dm] <infile> <outfile>\n";
    
    /** Used for debugging the application.
     */
    public static void main(String[] args) throws Exception
      {
        if(args.length != 3)
          {
              System.out.println(COMMAND_LINE_USAGE);
          }
        else
          {
            if(args[0].equalsIgnoreCase("d"))
              {
                FileInputStream in = new FileInputStream(args[1]);
                FileOutputStream out = new FileOutputStream(args[2]);
            
                byte[] b = new byte[in.available()];
                in.read(b);
                in.close();
            
                b = new Base64().getBinaryFromBase64Binary(b);
            
                out.write(b);
                out.close();
              }
            else if(args[0].equalsIgnoreCase("dm"))
              {
                FileInputStream in = new FileInputStream(args[1]);
                FileOutputStream out = new FileOutputStream(args[2]);
            
                String read = "";
            
                while(!read.endsWith("\n\n") && 
                      !read.endsWith("\r\r") && 
                      !read.endsWith("\r\n\r\n"))
                  {
                    int t = in.read();
                    if(t == -1)
                      throw new IOException("Unexpected EOF");
                    if(t == '\n' || t == '\r')
                      read += (char)t;
                    else
                      read = "";
                  }
            
                byte[] b = new byte[in.available()];
                in.read(b);
                in.close();            

                b = new Base64().getBinaryFromBase64Binary(b);
            
                out.write(b);
                out.close();
              }
            else if(args[0].equalsIgnoreCase("e"))
              {
                FileInputStream in = new FileInputStream(args[1]);
                FileOutputStream out = new FileOutputStream(args[2]);
            
                byte[] b = new byte[in.available()];
                in.read(b);
                in.close();
            
                b = new Base64().getBase64BinaryFromBinary(b);
            
                out.write(b);
                out.close();
              }
            else
              {
                System.out.println(COMMAND_LINE_USAGE);
              }
          }
      }
  }
