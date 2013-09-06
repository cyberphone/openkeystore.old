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

import java.util.Vector;

import java.util.regex.Pattern;

/**
 * Parses JSON into a DOM-like tree.
 * Only used internally.  The real stuff is supposed to use the
 * {@link JSONDocumentCache} and {@link JSONDocument} classes.
 * 
 */
class JSONParser
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
    
    static final Pattern INTEGER_PATTERN = Pattern.compile ("^0|[-]?[1-9][0-9]*$");
    static final Pattern BOOLEAN_PATTERN = Pattern.compile ("^true|false$");
    
    int index;
    
    int max_length;
    
    String json_data;

    JSONObject parse (byte[] json_utf8) throws IOException
      {
        json_data = new String (json_utf8, "UTF-8");
        index = 0;
        max_length = json_data.length ();
        scanFor (LEFT_CURLY_BRACKET);
        JSONObject root = new JSONObject ();
        scanObject (root);
        while (index < max_length)
          {
            if (!isWhiteSpace (json_data.charAt (index++)))
              {
                throw new IOException ("Improperly terminated JSON object");
              }
          }
        return root;
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
        while (testChar () != RIGHT_CURLY_BRACKET)
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
            holder.addProperty (name, value);
          }
        scan ();
        return new JSONValue (JSONTypes.OBJECT, holder);
      }

    JSONValue scanArray (String name) throws IOException
      {
        Vector<JSONValue> array = new Vector<JSONValue> ();
        JSONValue value = null;
        JSONValue last = null;
        while (testChar () != RIGHT_BRACKET)
          {
            if (last != null)
              {
                scanFor (COMMA_CHARACTER);
              }
            switch (scan ())
              {
                case LEFT_BRACKET:
                  // Limited use in protocols...
                  throw new IOException ("This system does not yet support multi-dimensional arrays");

                case LEFT_CURLY_BRACKET:
                  value = scanObject (new JSONObject ());
                  break;

                case DOUBLE_QUOTE:
                  value = scanQuotedString ();
                  break;

                default:
                  value = scanSimpleType ();
              }
            if (last != null && last.type != value.type)
              {
                throw new IOException ("Elements differ in type for array: " + name);
              }
            last = value;
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
        while (!isWhiteSpace (c = testChar ()) && c != COMMA_CHARACTER && c != RIGHT_BRACKET && c != RIGHT_CURLY_BRACKET)
          {
            temp_buffer.append (c);
            index++;
          }
        String result = temp_buffer.toString ();
        boolean number = INTEGER_PATTERN.matcher (result).matches ();
        if (!number && !BOOLEAN_PATTERN.matcher (result).matches ())
          {
            throw new IOException ("Expected integer or boolean, got: " + result);
          }
        return new JSONValue (number ? JSONTypes.INTEGER : JSONTypes.BOOLEAN, result);
      }

    JSONValue scanQuotedString () throws IOException
      {
        StringBuffer result = new StringBuffer ();
        while (true)
          {
            char c = nextChar ();
            if (c == DOUBLE_QUOTE)
              {
                break;
              }
            if (c == BACK_SLASH)
              {
                switch (c = nextChar ())
                  {
/* 
      Since JSON supplied as a part of web-page may need additional escaping
      while JSON data as a part of a protocol needs only needs to be parsable,
      Canonical JSON only supports the following two escape sequences.
*/
                    case '"':
                    case '\\':
                      break;

/*
      Removed: Redundant and potentially ambiguous
 
                    case '/':
                    case 'u':
                    case 'b':
                    case 'f':
                    case 'n':
                    case 'r':
                    case 't':
*/
                    default:
                      throw new IOException ("Unsupported escape:" + c);
                  }
              }
            result.append (c);
          }
        return new JSONValue (JSONTypes.STRING, result.toString ());
      }

    boolean isNumber (char c)
      {
        return c >= '0' && c <= '9';
      }

    char testChar () throws IOException
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
