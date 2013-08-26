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

/**
 * Parses JSON into a DOM-like tree.
 * Only used internally.
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
    
    int index;
    
    int max_length;
    
    String json_data;

    JSONHolder parse (byte[] json_utf8) throws IOException
      {
        json_data = new String (json_utf8, "UTF-8");
        index = 0;
        max_length = json_data.length ();
        scanFor (LEFT_CURLY_BRACKET);
        JSONHolder root = new JSONHolder ();
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
        return property.toString ();
      }
    

    JSONValue scanObject (JSONHolder holder) throws IOException
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
                  value = scanObject (new JSONHolder ());
                  break;

                case DOUBLE_QUOTE:
                  value = scanSimple (true);
                  break;

                case LEFT_BRACKET:
                  value = scanArray ();
                  break;

                default:
                  index--;
                  value = scanSimple (false);
              }
            holder.addProperty (name, value);
          }
        scan ();
        holder.reader = holder.properties.keySet ().iterator ();
        return new JSONValue (false, false, holder);
      }

    JSONValue scanArray () throws IOException
      {
        Vector array = null;
        JSONValue value = null;
        boolean next = false;
        while (testChar () != RIGHT_BRACKET)
          {
            if (next)
              {
                scanFor (COMMA_CHARACTER);
              }
            switch (scan ())
              {
                case LEFT_CURLY_BRACKET:
                  value = scanObject (new JSONHolder ());
                  break;

                case DOUBLE_QUOTE:
                  value = scanSimple (true);
                  break;

                default:
                  index--;
                  value = scanSimple (false);
              }
            if (!next)
              {
                next = true;
                array = new Vector ();
              }
            array.add (value.value);
          }
        scan ();
        if (next)
          {
            return new JSONValue (false, value.quoted, array);
          }
        return new JSONValue (false, false, new Vector<String> ());
      }

    JSONValue scanSimple (boolean quoted) throws IOException
      {
        StringBuffer simple = new StringBuffer ();
        if (quoted)
          {
            int start = index;
            while (scan () != DOUBLE_QUOTE)
              {
                
              }
            simple.append (json_data.substring (start, index - 1));
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
        return new JSONValue (true, quoted, simple.toString ());
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
