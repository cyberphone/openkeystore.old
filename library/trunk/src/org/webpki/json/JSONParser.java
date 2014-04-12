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
package org.webpki.json;

import java.io.IOException;

import java.util.Vector;

import java.util.regex.Pattern;

/**
 * Parses a JSON object given as a string into a DOM-like tree.
 * 
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
    static final char BACK_SLASH          = '\\';
    
    static final Pattern INTEGER_PATTERN          = Pattern.compile ("(0)|(-?[1-9][0-9]*)");
    static final Pattern BOOLEAN_PATTERN          = Pattern.compile ("true|false");
    static final Pattern DECIMAL_INITIAL_PATTERN  = Pattern.compile ("(\\+|-)?[0-9]+[\\.][0-9]+");
    static final Pattern DECIMAL_2DOUBLE_PATTERN  = Pattern.compile ("(\\+.*)|([-][0]*[\\.][0]*)");
    static final Pattern DOUBLE_PATTERN           = Pattern.compile ("[-+]?(([0-9]*\\.?[0-9]+)|([0-9]+\\.?[0-9]*))([eE][-+]?[0-9]+)?");
    
    int index;
    
    int max_length;
    
    String json_data;
    
    JSONParser () {}
    
    JSONObjectReader internal_parse (String json_string) throws IOException
      {
        json_data = json_string;
        max_length = json_data.length ();
        JSONObject root = new JSONObject ();
        if (testNextNonWhiteSpaceChar () == LEFT_BRACKET)
          {
            scan ();
            root.properties.put (null, scanArray ("outer array"));
          }
        else
          {
            scanFor (LEFT_CURLY_BRACKET);
            scanObject (root);
          }
        while (index < max_length)
          {
            if (!isWhiteSpace (json_data.charAt (index++)))
              {
                throw new IOException ("Improperly terminated JSON object");
              }
          }
        return new JSONObjectReader (root);
      }

    public static JSONObjectReader parse (String json_string) throws IOException
      {
        return new JSONParser ().internal_parse (json_string);
      }

    public static JSONObjectReader parse (byte[] json_utf8) throws IOException
      {
        return parse (new String (json_utf8, "UTF-8"));
      }

    String scanProperty () throws IOException
      {
        scanFor (DOUBLE_QUOTE);
        String property = (String) scanQuotedString ().value;
        if (property.length () == 0)
          {
            throw new IOException ("Empty property");
          }
        scanFor (COLON_CHARACTER);
        return property;
      }
    
    JSONValue scanObject (JSONObject holder) throws IOException
      {
        boolean next = false;
        while (testNextNonWhiteSpaceChar () != RIGHT_CURLY_BRACKET)
          {
            if (next)
              {
                scanFor(COMMA_CHARACTER);
              }
            next = true;
            String name = scanProperty ();
            JSONValue value;
            switch (scan ())
              {
                case LEFT_CURLY_BRACKET:
                  value = scanObject (new JSONObject ());
                  break;

                case DOUBLE_QUOTE:
                  value = scanQuotedString ();
                  break;

                case LEFT_BRACKET:
                  value = scanArray (name);
                  break;

                default:
                  value = scanSimpleType ();
              }
            holder.setProperty (name, value);
          }
        scan ();
        return new JSONValue (JSONTypes.OBJECT, holder);
      }

    JSONValue scanArray (String name) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        JSONValue value = null;
        boolean next = false;
        while (testNextNonWhiteSpaceChar () != RIGHT_BRACKET)
          {
            if (next)
              {
                scanFor (COMMA_CHARACTER);
              }
            else
              {
                next = true;
              }
            switch (scan ())
              {
                case LEFT_BRACKET:
                  value = scanArray (name);
                  break;

                case LEFT_CURLY_BRACKET:
                  value = scanObject (new JSONObject ());
                  break;

                case DOUBLE_QUOTE:
                  value = scanQuotedString ();
                  break;

                default:
                  value = scanSimpleType ();
              }
            array.add (value);
          }
        scan ();
        return new JSONValue (JSONTypes.ARRAY, array);
      }

    JSONValue scanSimpleType () throws IOException
      {
        index--;
        StringBuffer temp_buffer = new StringBuffer ();
        char c;
        while ((c = testNextNonWhiteSpaceChar ()) != COMMA_CHARACTER && c != RIGHT_BRACKET && c != RIGHT_CURLY_BRACKET)
          {
            if (isWhiteSpace (c = nextChar ()))
              {
                break;
              }
            temp_buffer.append (c);
          }
        String result = temp_buffer.toString ();
        if (result.length () == 0)
          {
            throw new IOException ("Missing argument");
          }
        JSONTypes type = JSONTypes.INTEGER;
        if (!INTEGER_PATTERN.matcher (result).matches ())
          {
            if (BOOLEAN_PATTERN.matcher (result).matches ())
              {
                type = JSONTypes.BOOLEAN;
              }
            else if (result.equals ("null"))
              {
                type = JSONTypes.NULL;
              }
            else if (DECIMAL_INITIAL_PATTERN.matcher (result).matches ())
              {
                type = DECIMAL_2DOUBLE_PATTERN.matcher (result).matches () ?
                                                          JSONTypes.DOUBLE : JSONTypes.DECIMAL;
              }
            else
              {
                type = JSONTypes.DOUBLE;
                if (!DOUBLE_PATTERN.matcher (result).matches ())
                  {
                    throw new IOException ("Undecodable argument: " + result);
                  }
              }
          }
        return new JSONValue (type, result);
      }

    JSONValue scanQuotedString () throws IOException
      {
        StringBuffer result = new StringBuffer ();
        while (true)
          {
            char c = nextChar ();
            if (c < ' ')
              {
                throw new IOException (c == '\n' ?
                   "Unterminated string literal" : "Unescaped control character: 0x" + Integer.toString (c, 16));
              }
            if (c == DOUBLE_QUOTE)
              {
                break;
              }
            if (c == BACK_SLASH)
              {
                switch (c = nextChar ())
                  {
                    case '"':
                    case '\\':
                    case '/':
                      break;

                    case 'b':
                      c = '\b';
                      break;

                    case 'f':
                      c = '\f';
                      break;

                    case 'n':
                      c = '\n';
                      break;

                    case 'r':
                      c = '\r';
                      break;

                    case 't':
                      c = '\t';
                      break;

                    case 'u':
                      c = 0;
                      for (int i = 0; i < 4; i++)
                        {
                          c = (char) ((c << 4) + getHexChar ());
                        }
                      break;

                    default:
                      throw new IOException ("Unsupported escape:" + c);
                  }
              }
            result.append (c);
          }
        return new JSONValue (JSONTypes.STRING, result.toString ());
      }

    char getHexChar () throws IOException
      {
        char c = nextChar ();
        switch (c)
          {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
              return (char) (c -'0');
              
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
              return (char) (c - 'a' + 10);
              
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
              return (char) (c - 'A' + 10);
          }
        throw new IOException ("Bad hex in \\u escape: " + c);
      }

    char testNextNonWhiteSpaceChar () throws IOException
      {
        int save = index;
        char c = scan ();
        index = save;
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
  }
