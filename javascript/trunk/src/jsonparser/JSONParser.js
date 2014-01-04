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

/*================================================================*/
/*                           JSONParser                           */
/*================================================================*/

function JSONParser ()
{
    this.LEFT_CURLY_BRACKET  = '{';
    this.RIGHT_CURLY_BRACKET = '}';
    this.BLANK_CHARACTER     = ' ';
    this.DOUBLE_QUOTE        = '"';
    this.COLON_CHARACTER     = ':';
    this.LEFT_BRACKET        = '[';
    this.RIGHT_BRACKET       = ']';
    this.COMMA_CHARACTER     = ',';
    this.BACK_SLASH          = '\\';

    this.INTEGER_PATTERN          = new RegExp ("^((0)|(-?[1-9][0-9]*))$");
    this.BOOLEAN_PATTERN          = new RegExp ("^(true|false)$");
    this.DECIMAL_INITIAL_PATTERN  = new RegExp ("^((\\+|-)?[0-9]+[\\.][0-9]+)$");
    this.DECIMAL_2DOUBLE_PATTERN  = new RegExp ("^((\\+.*)|([-][0]*[\\.][0]*))$");
    this.DOUBLE_PATTERN           = new RegExp ("^([-+]?(([0-9]*\\.?[0-9]+)|([0-9]+\\.?[0-9]*))([eE][-+]?[0-9]+)?)$");
}

/* JSONObjectReader */ JSONParser.prototype.parse = function (json_string)
{
    this.json_data = json_string;
    this.max_length = json_string.length;
    this.index = 0;
    var root = new JSONObject ();
    if (this.testNextNonWhiteSpaceChar () == this.LEFT_BRACKET)
      {
        this.scan ();
        var new_property = new Object;
        new_property.name = null;
        new_property.value = this.scanArray ("outer array");
        root.property_list[0] = new_property;
      }
    else
      {
        this.scanFor (this.LEFT_CURLY_BRACKET);
        this.scanObject (root);
      }
    while (this.index < this.max_length)
      {
        if (!this.isWhiteSpace (this.json_data.charAt (this.index++)))
          {
            JSONObject.prototype.bad ("Improperly terminated JSON object");
          }
      }
    return new JSONObjectReader (root);
};

/* String */ JSONParser.prototype.scanProperty = function ()
{
  this.scanFor (this.DOUBLE_QUOTE);
  var property = this.scanQuotedString ().value;
  if (property.length == 0)
    {
      JSONObject.prototype.bad ("Empty property");
    }
  this.scanFor (this.COLON_CHARACTER);
  return property;
};

/* JSONValue */ JSONParser.prototype.scanObject = function (/* JSONObject */ holder)
{
  /* boolean*/ var next = false;
  while (this.testNextNonWhiteSpaceChar () != this.RIGHT_CURLY_BRACKET)
    {
      if (next)
        {
          this.scanFor (this.COMMA_CHARACTER);
        }
      next = true;
      /* String */ var name = this.scanProperty ();
      /* JSONValue */ var value;
      switch (this.scan ())
        {
          case this.LEFT_CURLY_BRACKET:
            value = this.scanObject (new JSONObject ());
            break;

          case this.DOUBLE_QUOTE:
            value = this.scanQuotedString ();
            break;

          case this.LEFT_BRACKET:
            value = this.scanArray (name);
            break;

          default:
            value = this.scanSimpleType ();
        }
      holder.addProperty (name, value);
    }
  this.scan ();
  return new JSONValue (JSONTypes.OBJECT, holder);
};

/* JSONValue */ JSONParser.prototype.scanArray = function (/* String */ name)
{
  var arr_index = 0;
  /* Vector<JSONValue> */ var array = [] /* new Vector<JSONValue> () */;
  /* JSONValue */ var value = null;
  /* boolean */ var next = false;
  while (this.testNextNonWhiteSpaceChar () != this.RIGHT_BRACKET)
    {
      if (next)
        {
          this.scanFor (this.COMMA_CHARACTER);
        }
      else
        {
          next = true;
        }
      switch (this.scan ())
        {
          case this.LEFT_BRACKET:
            value = this.scanArray (name);
            break;

          case this.LEFT_CURLY_BRACKET:
            value = this.scanObject (new JSONObject ());
            break;

          case this.DOUBLE_QUOTE:
            value = this.scanQuotedString ();
            break;

          default:
            value = this.scanSimpleType ();
        }
      array[arr_index++] = value;
    }
  this.scan ();
  return new JSONValue (JSONTypes.ARRAY, array);
};

/* JSONValue */ JSONParser.prototype.scanSimpleType = function ()
{
  this.index--;
  /* StringBuffer */ var result = new String () /* StringBuffer () */;
  /* char */ var c;
  while ((c = this.testNextNonWhiteSpaceChar ()) != this.COMMA_CHARACTER && c != this.RIGHT_BRACKET && c != this.RIGHT_CURLY_BRACKET)
    {
      if (this.isWhiteSpace (c = this.nextChar ()))
        {
          break;
        }
      result += c;
    }
   if (result.length == 0)
    {
      JSONObject.prototype.bad ("Missing argument");
    }
  /* JSONTypes */ var type = JSONTypes.INTEGER;
  if (!this.INTEGER_PATTERN.test (result))
    {
      if (this.BOOLEAN_PATTERN.test (result))
        {
          type = JSONTypes.BOOLEAN;
        }
      else if (result == "null")
        {
          type = JSONTypes.NULL;
        }
      else if (this.DECIMAL_INITIAL_PATTERN.test (result))
        {
          type = this.DECIMAL_2DOUBLE_PATTERN.test (result) ?
                                           JSONTypes.DOUBLE : JSONTypes.DECIMAL;
        }
      else
        {
          type = JSONTypes.DOUBLE;
          if (!this.DOUBLE_PATTERN.test (result))
            {
              JSONObject.prototype.bad ("Undecodable argument: " + result);
            }
        }
    }
  return new JSONValue (type, result);
};

/* JSONValue */ JSONParser.prototype.scanQuotedString = function ()
{
  /* StringBuffer */ var result = new String () /* StringBuffer () */;
  while (true)
    {
      /* char */ var c = this.nextChar ();
      if (c < ' ')
        {
          JSONObject.prototype.bad ("Unescaped control character: " + c);
        }
      if (c == this.DOUBLE_QUOTE)
        {
          break;
        }
      if (c == this.BACK_SLASH)
        {
          switch (c = this.nextChar ())
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
                for (var i = 0; i < 4; i++)
                  {
                    c = ((c << 4) + this.getHexChar ());
                  }
                c = String.fromCharCode (c);
                break;

              default:
                JSONObject.prototype.bad ("Unsupported escape:" + c);
            }
        }
      result += c;
    }
  return new JSONValue (JSONTypes.STRING, result.toString ());
};

/* char */ JSONParser.prototype.getHexChar = function ()
{
  /* char */ var c = this.nextChar ();
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
        return c.charCodeAt (0) - 48;
        
      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f':
        return c.charCodeAt (0) - 87;
        
      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F':
        return c.charCodeAt (0) - 55;
    }
  JSONObject.prototype.bad ("Bad hex in \\u escape: " + c);
};

/* boolean */ JSONParser.prototype.isNumber  = function (/* char */ c)
{
  return c >= '0' && c <= '9';
};

/* char */ JSONParser.prototype.testNextNonWhiteSpaceChar = function ()
{
  /* int */ var save = this.index;
  /* char */ var c = this.scan ();
  this.index = save;
  return c;
};

/* void */ JSONParser.prototype.scanFor = function (/* char */ expected)
{
  /* char */ var c = this.scan ();
  if (c != expected)
    {
      JSONObject.prototype.bad ("Expected '" + expected + "' but got '" + c + "'");
    }
};

/* char */ JSONParser.prototype.nextChar = function ()
{
  if (this.index < this.max_length)
    {
      return this.json_data.charAt (this.index++);
    }
  JSONObject.prototype.bad ("Unexpected EOF reached");
};

/* boolean */ JSONParser.prototype.isWhiteSpace = function (/* char */ c)
{
  return c <= this.BLANK_CHARACTER;
};

/* char */ JSONParser.prototype.scan = function ()
{
  while (true)
    {
      /* char */ var c = this.nextChar ();
      if (this.isWhiteSpace (c))
        {
          continue;
        }
      return c;
    }
};
