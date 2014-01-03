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
package org.webpki.xml;

import java.io.IOException;

import java.math.BigInteger;
import java.math.BigDecimal;

import java.util.NoSuchElementException;
import java.util.GregorianCalendar;

import org.webpki.util.Base64;
import org.webpki.util.StringUtil;
import org.webpki.util.ISODateTime;

/**
 * Utility class making traversal of DOM documents easier in simple cases.
 * <p>The general use of this class is described in the documentation
 * for {@link DOMReaderHelper DOMReaderHelper}.
 * <p>Please note that the DOMAttributeReaderHelper returned by
 * {@link DOMReaderHelper#getAttributeHelper() DOMReaderHelper.getAttributeHelper()}
 * will follow the {@link DOMReaderHelper DOMReaderHelper}'s cursor, i.e. it
 * will always act on the current {@link DOMReaderHelper &quot;last visited element&quot;}
 * of the {@link DOMReaderHelper DOMReaderHelper}.
 * @see DOMReaderHelper
 * @see DOMReaderHelper#getAttributeHelper()
 */
public class DOMAttributeReaderHelper
  {
    private DOMReaderHelper reader;
  
    DOMAttributeReaderHelper(DOMReaderHelper reader)
      {
        this.reader = reader;
      }
  
    
    /*
     * TODO: To be documented.
     */
    public int getNumberOfAttributes () throws NoSuchElementException
      {
        return reader.current ().getAttributes ().getLength ();
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a <code>String</code>.
     * @param name The name of the attribute.
     * @return The value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     */
    public String getString (String name) throws NoSuchElementException
      {
        if (reader.current ().hasAttribute (name))
          {
            return reader.current ().getAttribute (name);
          }
        else
          {
            throw new NoSuchElementException ("No attribute " + name);
          }
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a <code>String</code>.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     */
    public String getStringConditional (String name, String defaultValue) throws NoSuchElementException
      {
          return reader.current ().hasAttribute (name) ? 
                 reader.current ().getAttribute (name) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a <code>String</code>.
     * @param name The name of the attribute.
     * @return The value of the attribute if it exists, null otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     */
    public String getStringConditional (String name) throws NoSuchElementException
      {
        return getStringConditional (name, null);
      }

    public byte[] getBinary (String name) throws NoSuchElementException, IOException
      {
        return new Base64 ().getBinaryFromBase64String (getString (name));
      }
    
    public byte[] getBinaryConditional (String name) throws NoSuchElementException, IOException
      {
        String value = getStringConditional (name);
        return value == null ? null : new Base64 ().getBinaryFromBase64String (value);
      }
    

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>int</code>.
     * @param name The name of the attribute.
     * @return The <code>int</code> value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws NumberFormatException If the value is not a valid <code>int</code>.
     */
    public int getInt (String name) throws NoSuchElementException, NumberFormatException
      {
        return Integer.parseInt (getString (name));
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>int</code>.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid <code>int</code>.
     */
    public int getIntConditional (String name, int defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? Integer.parseInt (s) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>int</code>.
     * @param name The name of the attribute.
     * @return The value of the attribute if it exists, 0 otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid <code>int</code>.
     */
    public int getIntConditional (String name) throws NoSuchElementException
      {
        return getIntConditional (name, 0);
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>boolean</code>.
     * @param name The name of the attribute.
     * @return The <code>int</code> value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws IllegalArgumentException If the value is not a valid <code>boolean</code>.
     */
    public boolean getBoolean (String name) throws NoSuchElementException
      {
        return DOMUtil.booleanValue (getString (name));
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>boolean</code>.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws IllegalArgumentException If the value is not a valid <code>boolean</code>.
     */
    public boolean getBooleanConditional (String name, boolean defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? DOMUtil.booleanValue (s) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an <code>boolean</code>.
     * @param name The name of the attribute.
     * @return The value of the attribute if it exists, 0 otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws IllegalArgumentException If the value is not a valid <code>boolean</code>.
     */
    public boolean getBooleanConditional (String name) throws NoSuchElementException
      {
        return getBooleanConditional (name, false);
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a {@link BigDecimal BigDecimal}.
     * @param name The name of the attribute.
     * @return The {@link BigDecimal BigDecimal} value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimal (String name) throws NoSuchElementException, NumberFormatException
      {
        return new BigDecimal (getString (name));
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a {@link BigDecimal BigDecimal}.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimalConditional (String name, BigDecimal defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? new BigDecimal (s) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a {@link BigDecimal BigDecimal}.
     * @param name The name of the attribute.
     * @return The value of the attribute if it exists, null otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimalConditional (String name) throws NoSuchElementException
      {
        return getBigDecimalConditional (name, null);
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as an {@link BigInteger BigInteger}.
     * @param name The name of the attribute.
     * @return The {@link BigInteger BigInteger} value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws NumberFormatException If the value is not a valid {@link BigInteger BigInteger}.
     */
    public BigInteger getBigInteger (String name) throws NoSuchElementException, NumberFormatException
      {
        return new BigInteger (getString (name));
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a {@link BigInteger BigInteger}.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigInteger BigInteger}.
     */
    public BigInteger getBigIntegerConditional (String name, BigInteger defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? new BigInteger (s) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a {@link BigInteger BigInteger}.
     * @param name The name of the attribute.
     * @return The value of the attribute if it exists, null otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigInteger BigInteger}.
     */
    public BigInteger getBigIntegerConditional (String name) throws NoSuchElementException
      {
        return getBigIntegerConditional (name, null);
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a 
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     * @param name The name of the attribute.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws IOException If the value cannot be parsed as
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTime (String name) throws NoSuchElementException, IOException
      {
        return ISODateTime.parseDateTime (getString (name));
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a 
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     * @param name The name of the attribute.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws IOException If the value cannot be parsed as
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTimeConditional (String name, GregorianCalendar defaultValue) throws IOException
      {
        String s = getStringConditional (name);
        return s != null ? ISODateTime.parseDateTime (s) : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;} as a 
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     * @param name The name of the attribute.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         value of the attribute if it exists, null otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws IOException If the value cannot be parsed as
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTimeConditional (String name) throws IOException
      {
        return getDateTimeConditional (name, null);
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;}, multiplied by 1000 and truncated, as
     * a <code>long</code>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @param name The name of the attribute.
     * @return The {@link BigInteger BigInteger} value of the attribute.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;} or
     *                                if that element has no attribute named <i>name</i>.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public long getMoney (String name) throws NoSuchElementException, NumberFormatException
      {
        return getBigDecimal (name).movePointRight (4).longValue ();
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;},
     * multiplied by 1000 and truncated, as
     * a <code>long</code>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @param defaultValue The value to use if the attribute does not exist.
     * @return The value of the attribute if it exists, <i>defaultValue</i> otherwise 
     *         (&quot;exists&quot; meaning being specified in the document or having
     *         a default value in the schema or DTD, known to the DOM implementation).
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public long getMoneyConditional (String name, long defaultValue) throws NoSuchElementException
      {
        BigDecimal t = getBigDecimalConditional (name);
        return t != null ? t.movePointRight (4).longValue () : defaultValue;
      }

    /**
     * Get an attribute of the {@link DOMReaderHelper &quot;last visited element&quot;}, multiplied by 1000 and truncated, as
     * a <code>long</code>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @return The value of the attribute if it exists, 0 otherwise.
     * @throws NoSuchElementException If there is no 
     *                                {@link DOMReaderHelper &quot;last visited element&quot;}.
     * @throws NumberFormatException If the value is not a valid {@link BigDecimal BigDecimal}.
     */
    public long getMoneyConditional (String name) throws NoSuchElementException
      {
        return getMoneyConditional (name, 0);
      }
    /*
     * TODO: To be documented.
     */
    public String[] getList (String name) throws NoSuchElementException
      {
        return StringUtil.tokenVector (getString (name));
      }
    
    /*
     * TODO: To be documented.
     */
    public String[] getListConditional (String name) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? StringUtil.tokenVector (s) : null;
      }
  }
