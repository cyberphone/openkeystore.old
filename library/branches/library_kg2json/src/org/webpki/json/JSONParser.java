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

import org.webpki.util.ArrayUtil;

/**
 * Parses JSON into a DOM-like tree.
 */
public class JSONParser
  {
    static final char LEFT_CURLY_BRACKET  = '{';
    static final char RIGHT_CURLY_BRACKET = '}';
    static final char BLANK_CHARACTER     = ' ';
    static final char DOUBLE_QUOTE        = '"';
    static final char COLON_CHARACTER     = ':';
    static final char LEFT_BRACKET        = '[';
    static final char RIGHT_BRACKET       = ']';
    static final char COMMA_CHARACTER     = ',';
    
    int index;
    int max_length;
    String json_data;
    
    public void parse (byte[] json_utf8) throws IOException
      {
        json_data = new String (json_utf8, "UTF-8");
        index = 0;
        max_length = json_data.length ();
        scanFor (LEFT_CURLY_BRACKET);
        scanProperty ();
        scanFor (LEFT_CURLY_BRACKET);
        scanObject ();
        scanFor (RIGHT_CURLY_BRACKET);
        while (index < max_length)
          {
            if (!isWhiteSpace (json_data.charAt (index++)))
              {
                throw new IOException ("Improperly terminated JSON object");
              }
          }
      }

    void scanProperty () throws IOException
      {
        scanFor (DOUBLE_QUOTE);
        StringBuffer property = new StringBuffer ();
        char c;
        while ((c = nextChar ()) != DOUBLE_QUOTE)
          {
            property.append (c);
          }
        if (property.length () == 0)
          {
            throw new IOException ("Empty property");
          }
        scanFor (COLON_CHARACTER);
      }
    

    void scanObject () throws IOException
      {
        boolean next = false;
        while (testChar () != RIGHT_CURLY_BRACKET)
          {
            if (next)
              {
                scanFor(COMMA_CHARACTER);
              }
            next = true;
            scanProperty ();
            switch (scan ())
              {
                case LEFT_CURLY_BRACKET:
                  scanObject ();
                  break;

                case DOUBLE_QUOTE:
                  scanSimple (true);
                  break;

                case LEFT_BRACKET:
                  scanArray ();
                  break;

                default:
                  index--;
                  scanSimple (false);
              }
          }
        scan ();
      }

    void scanArray () throws IOException
      {
        boolean next = false;
        while (testChar ()!= RIGHT_BRACKET)
          {
            if (next)
              {
                scanFor (COMMA_CHARACTER);
              }
            next = true;
            switch (scan ())
              {
                case LEFT_CURLY_BRACKET:
                  scanObject ();
                  break;

                case DOUBLE_QUOTE:
                  scanSimple (true);
                  break;

                default:
                  index--;
                  scanSimple (false);
              }
          }
        scan ();
      }

    void scanSimple (boolean quoted) throws IOException
      {
        StringBuffer simple = new StringBuffer ();
        if (quoted)
          {
            int start = index;
            while (scan () != DOUBLE_QUOTE)
              {
                
              }
            simple.append (json_data.substring (start, index));
          }
        else
          {
            char c;
            while (!isWhiteSpace (c = testChar ()) && c != COMMA_CHARACTER && c != RIGHT_BRACKET && c != RIGHT_CURLY_BRACKET)
              {
                simple.append (c);
                index++;
              }
            if (simple.length () == 0)
              {
                throw new IOException ("Missing value");
              }
          }
      }

    char testChar () throws IOException
      {
        char c = scan ();
        index--;
        return c;
      }

    void scanFor (char expected) throws IOException
      {
        char c = scan ();
        if (c != expected)
          {
            throw new IOException ("Expected '" + expected + "' but got '" + c + "'");
          }
      }

    char nextChar () throws IOException
      {
        if (index < max_length)
          {
            return json_data.charAt (index++);
          }
        throw new IOException ("Unexpected EOF reached");
      }

    boolean isWhiteSpace (char c)
      {
        return c <= BLANK_CHARACTER;
      }

    char scan () throws IOException
      {
        while (true)
          {
            char c = nextChar ();
            if (isWhiteSpace (c))
              {
                continue;
              }
            return c;
          }
      }

    public static void main (String[] argc)
      {
        try
          {
            JSONParser parser = new JSONParser ();
            parser.parse (ArrayUtil.readFile (argc[0]));
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
