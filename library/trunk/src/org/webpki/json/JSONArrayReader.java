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
import java.math.BigDecimal;
import java.math.BigInteger;

import java.util.Vector;

/**
 * For writing array elements.
 */
public class JSONArrayReader
  {
    Vector<JSONValue> array;

    int index;

    JSONArrayReader (Vector<JSONValue> array)
      {
        this.array = array;
      }

    public boolean hasMore ()
      {
        return index < array.size ();
      }

    void inRangeCheck () throws IOException
      {
        if (!hasMore ())
          {
            throw new IOException ("Trying to read past of array limit: " + index);
          }
      }
    
    Object get (JSONTypes expected_type) throws IOException
      {
        inRangeCheck ();
        JSONValue value = array.elementAt (index++);
        if (!expected_type.isCompatible (value.type))
          {
            throw new IOException ("Incompatible request: " + expected_type + " versus " + value.type);
          }
        return value.value;
      }

    public String getString () throws IOException
      {
        return (String) get (JSONTypes.STRING);
      }

    public int getInt () throws IOException
      {
        return Integer.parseInt ((String) get (JSONTypes.INTEGER));
      }

    public BigInteger getBigInteger () throws IOException
      {
        return new BigInteger ((String) get (JSONTypes.INTEGER));
      }

    public BigDecimal getBigDecimal () throws IOException
      {
        return new BigDecimal ((String) get (JSONTypes.DECIMAL));
      }

    public double getDouble () throws IOException
      {
        return new Double ((String) get (JSONTypes.FLOATING_POINT));
      }

    public boolean getBoolean () throws IOException
      {
        return new Boolean ((String) get (JSONTypes.BOOLEAN));
      }

    public boolean getIfNULL () throws IOException
      {
        if (getElementType () == JSONTypes.NULL)
          {
            scanAway ();
            return true;
          }
        return false;
      }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray () throws IOException
      {
        return new JSONArrayReader ((Vector<JSONValue>)get (JSONTypes.ARRAY));
      }

    public JSONTypes getElementType () throws IOException
      {
        inRangeCheck ();
        return array.elementAt (index).type;
      }

    public JSONObjectReader getObject () throws IOException
      {
        return new JSONObjectReader ((JSONObject) get (JSONTypes.OBJECT));
      }

    public void scanAway () throws IOException
      {
        get (getElementType ());
      }
  }
