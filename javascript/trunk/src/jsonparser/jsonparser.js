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
/*                            JSONTypes                           */
/*================================================================*/

var JSONTypes = 
  {
	NULL:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.NULL;}
	  },
	BOOLEAN:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.BOOLEAN;}
	  },
	INTEGER:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.INTEGER;}
	  },
	DECIMAL:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER;}
	  },
	DOUBLE:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.DOUBLE || o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER;}
	  },
    STRING:
	  {
		"complex" : function () { return false;},
		"compatible" : function (o) { return o == JSONTypes.STRING;}
	  },
    ARRAY:
	  {
		"complex" : function () { return true;},
		"compatible" : function (o) { return o == JSONTypes.ARRAY;}
	  },
    OBJECT:
	  {
		"complex" : function () { return true;},
		"compatible" : function (o) { return o == JSONTypes.OBJECT;}
	  }
  };


/*================================================================*/
/*                            JSONValue                           */
/*================================================================*/

function JSONValue (type, value)
{
	this.type = type;
	this.value = value;
}


/*================================================================*/
/*                           JSONObject                           */
/*================================================================*/

function JSONObject ()
{
	this.property_list = [];
	this.read_flag = new Object ();
	this.index = 0;
}

JSONObject.prototype.addProperty = function (name, value)
{
	if (!(value instanceof JSONValue))
	{
		JSONObject.prototype.bad ("Wrong value type: " + value);
	}
	console.debug("V=" + value.type);
	var o = new Object;
	o.name = name;
	o.value = value;
	for (i = 0; i < this.index; i++)
	{
		if (this.property_list[i].name == name)
		{
			JSONObject.prototype.bad ("Property already defined: " + name);
		}
	}
	this.property_list[this.index++] = o;
	this.read_flag.name = null;
};

JSONObject.prototype.bad = function (message)
{
	throw "JSONException: " + message;
};

JSONObject.prototype.getProperty = function (name)
{
	for (i = 0; i < this.index; i++)
	{
		if (this.property_list[i].name == name)
		{
			return this.property_list[i].value;
		}
	}
	this.bad ("Property undefined: " + name);
};

JSONObject.prototype.getLength = function ()
{
	return this.property_list.length;
};


/*================================================================*/
/*                           JSONParser                           */
/*================================================================*/

function JSONParser ()
{
	this.LEFT_BRACKET = '[';
}

/* JSONObjectReader */ JSONParser.prototype.parse = function (json_string)
{
	this.json_data = json_string;
	this.max_length = json_string.length;
	this.index = 0;
    this.root = new JSONObject ();
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
//    return new JSONObjectReader (root);
    return root;
};

/* String */ JSONParser.prototype.scanProperty = function ()
{
  scanFor (DOUBLE_QUOTE);
  var property = scanQuotedString ().value;
  if (property.length == 0)
    {
      throw new IOException ("Empty property");
    }
  scanFor (COLON_CHARACTER);
  return property;
};

/* JSONValue */ JSONParser.prototype.scanObject = function (/* JSONObject */ holder)
{
  /* boolean*/ var next = false;
  while (testNextNonWhiteSpaceChar () != RIGHT_CURLY_BRACKET)
    {
      if (next)
        {
          scanFor(COMMA_CHARACTER);
        }
      next = true;
      /* String */ var name = scanProperty ();
      /* JSONValue */ var value;
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
};

/* JSONValue */ JSONParser.prototype.scanArray = function (/* String */ name)
{
  /* Vector<JSONValue> */ var array = [] /* new Vector<JSONValue> () */;
  /* JSONValue */ var value = null;
  /* boolean */ var next = false;
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
};

/* JSONValue */ JSONParser.prototype.scanSimpleType = function ()
{
  this.index--;
  /* StringBuffer */ temp_buffer = new String () /* StringBuffer () */;
  /* char */ var c;
  while ((c = testNextNonWhiteSpaceChar ()) != COMMA_CHARACTER && c != RIGHT_BRACKET && c != RIGHT_CURLY_BRACKET)
    {
      if (isWhiteSpace (c = nextChar ()))
        {
          break;
        }
      temp_buffer += c;
    }
  /* String */ var result = temp_buffer.toString ();
  if (result.length == 0)
    {
      JSONParser.prototype.bad ("Missing argument");
    }
  /* JSONTypes */ var type = JSONTypes.INTEGER;
/*
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
          try
            {
              Double.parseDouble (result);
              type = JSONTypes.DOUBLE;
            }
          catch (NumberFormatException e)
            {
              throw new IOException ("Undecodable argument: " + result + " msg=" + e.getMessage ());
            }
        }
    }
*/
  return new JSONValue (type, result);
};

/* JSONValue */ JSONParser.prototype.scanQuotedString = function ()
{
  /* StringBuffer */ var result = new String () /* StringBuffer () */;
  while (true)
    {
      /* char */ var c = nextChar ();
      if (c < ' ')
        {
          JSONObject.prototype.bad ("Unescaped control character: " + c);
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
                for (var i = 0; i < 4; i++)
                  {
                    c = ((c << 4) + getHexChar ());
                  }
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
  /* char */ var c = nextChar ();
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
        return c -'0';
        
      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f':
        return c - 'a' + 10;
        
      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F':
        return c - 'A' + 10;
    }
  JSONObject.prototype.bad ("Bad hex in \\u escape: " + c);
};

/* boolean */ JSONParser.prototype.isNumber  = function (/ *char */ c)
{
  return c >= '0' && c <= '9';
};

/* char */ JSONParser.prototype.testNextNonWhiteSpaceChar = function ()
{
  /* int */ var save = this.index;
  /* char */ var c = scan ();
  this.index = save;
  return c;
};

/* void */ JSONParser.prototype.scanFor = function (/* char */ expected)
{
  /* char */ var c = scan ();
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
  JSONParser.prototype.bad ("Unexpected EOF reached");
};

/* boolean */ JSONParser.prototype.sWhiteSpace = function (/* char */ c)
{
  return c <= BLANK_CHARACTER;
};

/* char */ JSONParser.prototype.scan = function ()
{
  while (true)
    {
      /* char */ var c = nextChar ();
      if (isWhiteSpace (c))
        {
          continue;
        }
      return c;
    }
};

var jo = new JSONObject ();
jo.addProperty("one", new JSONValue (JSONTypes.INTEGER, 3));
jo.addProperty("two", new JSONValue (JSONTypes.STRING, "hi"));
console.debug ("T=" + jo.getProperty ("two").type + " V="+ jo.getProperty ("two").value)
//jo.addProperty("two", new JSONValue (JSONTypes.INTEGER, 3));
var jo1 = new JSONObject ();
jo1.addProperty("one1", new JSONValue (JSONTypes.INTEGER, 4));
jo1.addProperty("two2", new JSONValue (JSONTypes.OBJECT, jo));
jo1.addProperty("tree", new JSONValue (JSONTypes.STRING, "ghghg"));
console.debug ("l=" + jo1.getLength());
console.debug ("l=" + jo.getLength());

var indent = 0;
function loopa (o)
{
	var space = "";
	for (var i = 0; i < indent; i++)
	{
		space += ' ';
	}
	for (var i = 0; i < o.index; i++)
	{
		var elem = o.property_list[i];
		var string = space + '"' + elem.name + '":';
		if (elem.value.type == JSONTypes.OBJECT)
		{
			console.debug (string);
			console.debug (space + '  {');
			indent += 4;
			loopa (elem.value.value);
			indent -= 4;
			console.debug (space + '  }');
		}
		else
		{
			string += ' ';
			if (elem.value.type == JSONTypes.INTEGER)
			{
				string += elem.value.value; 
			}
			else if (elem.value.type == JSONTypes.STRING)
			{
				string += '"' + elem.value.value + '"'; 
			}
			console.debug (string);
		}
	}
}

loopa (jo1);
console.debug (JSONTypes.DOUBLE.compatible(JSONTypes.OBJECT));

new JSONParser ().parse ('{"hello": "world!"}');
