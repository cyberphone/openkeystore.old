/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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

import java.util.NoSuchElementException;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.SimpleTimeZone;
import java.math.BigInteger;
import java.math.BigDecimal;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.webpki.util.Base64;
import org.webpki.util.StringUtil;

/**
 * Utility class making traversal of DOM documents easier in simple cases.
 * <p>This class holds the state of a cursor navigating the tree and provides
 * a set of methods for accessing/converting the contents of elements.
 * <p>The cursor is moved after a successful call to <code>getNext()</code>, 
 * <code>get<i>Datatype</i>()</code> or <code>get<i>Datatype</i>Conditional()</code>, 
 * i.e. after the value is read.
 * <p>{@link #getChild() getChild} and the {@link #getAttributeHelper DOMAttributeReaderHelper} 
 * will act on the <a name="last"><code><b>&quot;last visited element&quot;</b></code></a>, hereby defined to mean the
 * element that the cursor pointed at before the last <code>getNext()</code>, 
 * <code>get<i>Datatype</i>()</code> or <code>get<i>Datatype</i>Conditional()</code> call, if any.
 * This allows code like
 * <pre>   helper.getNext(&quot;orderline&quot;);
 *   String item = helper.getAttributeHelper().getString(&quot;item&quot;);</pre>
 * to extract the attribute <code>item</code> of element <code>orderline</code>.
 * <h3>A small example</h3>
 * <p><pre>
 *   DOMReaderHelper helper = new DOMReaderHelper(e);
 *
 *   helper.getNext(&quot;order&quot;);
 *
 *   // Go one level down in the structure.
 *   helper.getChild();
 *
 *   buyer = helper.getString(&quot;buyer&quot;);
 *
 *   buyerDUNS = helper.getAttributeHelper().getInt(&quot;duns&quot;);
 *
 *   comment = helper.getStringConditional(&quot;comment&quot;);
 *   ...</pre>
 * which parses the structure
 * <pre>
 *   &lt;example:order xmlns:example=&quot;...&quot;&gt;
 *       &lt;buyer duns=&quot;12345&quot;&gt;John Doe&lt;/buyer&gt;
 *       &lt;comment&gt;Urgent!&lt;/comment&gt;
 *       ...
 *   &lt;/example:order&gt;</pre>
 * This example code comes from an example included in the distribution
 * to illustrate how to write an {@link XMLObjectWrapper XMLObjectWrapper}.
 */
public class DOMReaderHelper
  {
    private static final int STATE_BEFORE = -1;
    private static final int STATE_AT = 0;
    private static final int STATE_AFTER = 1;
    private static final int STATE_IN_EMPTY_SET = 2;
  
    private int state = STATE_BEFORE;
    private Element __current;

    private boolean was_CDATA;  // Really ugly but works...
    
    public DOMReaderHelper (Element e)
      {
        __current = e;
      }

    private String text (String name) throws NoSuchElementException
      {
        was_CDATA = false;
        Element t = current();
      
        NodeList l = t.getChildNodes();
        
        if(name != null && !name.equals(DOMUtil.getLocalName(t)))
          {
            throw new NoSuchElementException("Not at element " + name + ": " + t.getNodeName() + ".");
          }
        
        if(l.getLength() == 0)
          {
            return null;
          }
        StringBuffer s = new StringBuffer ();
        was_CDATA = true;
        for (int i = 0; i < l.getLength (); i++)
          {
            Node n = l.item(i);
            short nt = n.getNodeType();
            if (nt != Node.TEXT_NODE && nt != Node.CDATA_SECTION_NODE)
              {
                throw new NoSuchElementException("Not at a Text/CDATA element: " + t.getNodeName() + ".");
              }
            if (nt == Node.TEXT_NODE)
              {
                was_CDATA = false;
              }
            s.append (n.getNodeValue ());
          }
        return s.toString ();
      }
    
    private String text () throws NoSuchElementException
      {
        return text (null);
      }
    
    private void next (String name) throws NoSuchElementException
      {
        switch(state)
          {
            case STATE_BEFORE:
              // We are before the first sibling => go to first sibling.
              state = STATE_AT;
              break;
            case STATE_AT:
              // We are at a sibling => go to next sibling if any, 
              //                        go after current if current is the last.
              Element t = DOMUtil.nextSiblingElement(__current);
              if(t != null)
                {
                  __current = t;
                }
              else
                {
                  // Changed 20011001: should never go STATE_AFTER, all calls
                  // to next are followed by a call to current() which will then throw
                  // an exception =>
                  // TODO: remove STATE_AFTER completely
                  //state = STATE_AFTER;
                  throw new NoSuchElementException("No more sibling elements.");
                }
              break;
            case STATE_AFTER:
              // We are after the last sibling => this method call is "illegal".
              throw new NoSuchElementException("No more sibling elements.");
            case STATE_IN_EMPTY_SET:
              // We in the child set of an element without children => this method call is "illegal".
              throw new NoSuchElementException("No elements.");
            default:
              throw new RuntimeException("Illegal state.");
          }
        if(name != null && !name.equals(DOMUtil.getLocalName(__current)))
          {
            throw new NoSuchElementException("Not at element " + name + ": " + __current.getNodeName() + ".");
          }
      }

    private void next () throws NoSuchElementException
      {
        next(null);
      }
    
    
    private Element levelDown () throws NoSuchElementException
      {
        if(state == STATE_AT || state == STATE_BEFORE)
          {
            Element t = DOMUtil.firstChildElement(__current);
            if(t != null)
              {
                state = STATE_BEFORE;
                return __current = t;
              }
            else
              {
                state = STATE_IN_EMPTY_SET;
                return null;
              }
          }
        else
          {
            throw new NoSuchElementException("Not at an element.");
          }
      }
    
    private Element levelUp () throws NoSuchElementException
      {
        if (state != STATE_IN_EMPTY_SET)
          {
            __current = (Element)__current.getParentNode();
          }
        state = STATE_AT;
        return __current;
      }
    
    public Element current () throws NoSuchElementException
      {
        if (state != STATE_AT)
          {
            throw new NoSuchElementException("Not at an element.");
          }
        else
          {
            return __current;
          }
      }
    
    /* *******************************************************************************
          Navigation
       ******************************************************************************* */
    /**
     * Moves the cursor to the first child of the <a href="#last">&quot;last visited element&quot;</a>.
     * @throws NoSuchElementException If there is no <a href="#last">&quot;last visited element&quot;</a>.
     */
    public void getChild () throws NoSuchElementException
      {
        levelDown ();
      }
    
    /**
     * Moves the cursor to the last element at which {@link #getChild getChild} was called.
     */
    public void getParent ()
      {
        levelUp ();
      }
    
    /**
     * Check if the <a href="#last">&quot;last visited element&quot;</a> has more siblings.
     * @return true iff the <a href="#last">&quot;last visited element&quot;</a> has more siblings.
     */
    public boolean hasNext ()
      {
        return state == STATE_BEFORE || 
               (state == STATE_AT && DOMUtil.nextSiblingElement(__current) != null);
      }
    
    /**
     * Check if the next sibling of <a href="#last">&quot;last visited element&quot;</a>
     * has local name <code><i>name</i></code> (and if exists at all).
     * @return true iff the <a href="#last">&quot;last visited element&quot;</a> has more siblings,
     *                  and the next sibling has local name <code><i>name</i></code>.
     */
    public boolean hasNext (String name)
      {
        Element next = (state == STATE_BEFORE) ? 
                         __current :
                         (state == STATE_AT)  ?
                           DOMUtil.nextSiblingElement(__current) :
                           null;

        return next != null && DOMUtil.getLocalName (next).equals (name);
      }
    
    /**
     * Moves the cursor to the next {@link Element Element}.
     * @return The current element.
     * @throws NoSuchElementException If there are no more elements.
     */
    public Element getNext() throws NoSuchElementException
      {
        next ();
        return current ();
      }
    
    /**
     * Checks that the current element has local name <i>name</i> and moves the cursor to the next element.
     * @return The current element.
     * @param name The local element name expected.
     * @throws NoSuchElementException If the current element's local name is not <i>name</i> or
     *                               if there are no more elements.
     */
    public Element getNext (String name) throws NoSuchElementException
      {
        next (name);
        return current ();
      }

    public XMLCookie getXMLCookie (String name) throws NoSuchElementException
      {
        return new XMLCookie (getNext (name));
      }
    
    public XMLCookie getXMLCookie () throws NoSuchElementException
      {
        return new XMLCookie (getNext ());
      }
    
    public String getNamespace()
      {
        return DOMUtil.getDefiningNamespace(current());
      }

    /* *******************************************************************************
          Attributes
       ******************************************************************************* */
    private DOMAttributeReaderHelper attributeHelper = new DOMAttributeReaderHelper(this);
    
    /**
     * Get the {@link DOMAttributeReaderHelper DOMAttributeReaderHelper} of this 
     * <code>DOMReaderHelper</code>.
     * <p>The {@link DOMAttributeReaderHelper DOMAttributeReaderHelper} gives access
     * to the attributes of the <a href="#last">&quot;last visited element&quot;</a>.
     * <p>Please note that the DOMAttributeReaderHelper returned will follow this 
     * DOMReaderHelper's cursor, i.e. it will always act on the current 
     * {@link DOMReaderHelper &quot;last visited element&quot;}
     * of this DOMReaderHelper.
     */
    public DOMAttributeReaderHelper getAttributeHelper()
      {
        return attributeHelper;
      }


    public boolean wasCDATA ()
      {
        return was_CDATA;
      }
    /**
     * Get the text contents of the current {@link Element Element}.
     * @return The text contents of the current {@link Element Element},
     *         null if the element is empty.
     * @throws NoSuchElementException if the current element has non-text content or
     *                                if there is no current element.
     */
    public String getString() throws NoSuchElementException
      {
        next();
        return text();
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element},
     *         null if the element is empty.
     * @throws NoSuchElementException if the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     */
    public String getString(String name) throws NoSuchElementException
      {
        next();
        return text(name);
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return The text contents of the current {@link Element Element}, if it exists, 
     *         is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException if the current element has local name <i>name</i> but
     *                               has non-text content.
     */
    public String getStringConditional(String name) throws NoSuchElementException
      {
        return hasNext (name) ? getString () : null;
      }
    
    /**
     * Get the text contents of the current {@link Element Element} as an <code>int</code>.
     * @return The text contents of the current {@link Element Element}, as an <code>int</code>.
     * @throws NoSuchElementException if the current element has non-text content or
     *                               if there is no current element.
     * @throws NumberFormatException if the current element is empty or a text element that cannot 
     *                               be parsed as an <code>int</code>.
     */
    public int getInt() throws NoSuchElementException
      {
        return Integer.parseInt(getString());
      }

    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as an <code>int</code>.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element}, as an <code>int</code>.
     * @throws NoSuchElementException if the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws NumberFormatException if the current element has local name <i>name</i> and is empty or has text-only content
     *                               that cannot be parsed as an <code>int</code>.
     */
    public int getInt(String name) throws NoSuchElementException
      {
        return Integer.parseInt(getString(name));
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>,
     * as an <code>int</code>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @param defaultValue The <code>int</code> value to return if the element does not exist.
     * @return The text contents of the current {@link Element Element} as an <code>int</code>,
     *         if it exists, is non-empty and has local name <i>name</i>, <i>defaultValue</i> otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws NumberFormatException If the current element has local name <i>name</i> and has text-only content
     *                               that cannot be parsed as an <code>int</code>.
     */
    public int getIntConditional(String name, int defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional(name);
        return s != null ? Integer.parseInt(s) : defaultValue;
      }

    /**
     * Get the text contents of the current {@link Element Element} as an <code>boolean</code>.
     * @return The text contents of the current {@link Element Element}, as an <code>boolean</code>.
     * @throws NoSuchElementException if the current element has non-text content or
     *                               if there is no current element.
     * @throws IllegalArgumentException if the current element is empty or a text element that cannot 
     *                               be parsed as an <code>boolean</code>.
     */
    public boolean getBoolean () throws NoSuchElementException
      {
        return DOMUtil.booleanValue (getString ());
      }

    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as an <code>boolean</code>.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element}, as an <code>boolean</code>.
     * @throws NoSuchElementException if the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws IllegalArgumentException if the current element has local name <i>name</i> and is empty or has text-only content
     *                               that cannot be parsed as an <code>boolean</code>.
     */
    public boolean getBoolean (String name) throws NoSuchElementException
      {
        return DOMUtil.booleanValue (getString (name));
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>,
     * as an <code>boolean</code>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @param defaultValue The <code>boolean</code> value to return if the element does not exist.
     * @return The text contents of the current {@link Element Element} as an <code>boolean</code>,
     *         if it exists, is non-empty and has local name <i>name</i>, <i>defaultValue</i> otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws IllegalArgumentException If the current element has local name <i>name</i> and has text-only content
     *                               that cannot be parsed as an <code>boolean</code>.
     */
    public boolean getBooleanConditional (String name, boolean defaultValue) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? DOMUtil.booleanValue(s) : defaultValue;
      }

    /**
     * Get the text contents of the current {@link Element Element} as a {@link BigDecimal BigDecimal}.
     * @return The text contents of the current {@link Element Element}, as a {@link BigDecimal BigDecimal}.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element is empty or a text element that cannot 
     *                               be parsed as a {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimal () throws NoSuchElementException
      {
        return new BigDecimal (getString ());
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as a {@link BigDecimal BigDecimal}.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element}, as a {@link BigDecimal BigDecimal}.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element has local name <i>name</i> and is empty or has text-only content
     *                               that cannot be parsed as a {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimal (String name) throws NoSuchElementException
      {
        return new BigDecimal (getString (name));
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>,
     * as a {@link BigDecimal BigDecimal}.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return The text contents of the current {@link Element Element} as a {@link BigDecimal BigDecimal},
     *         if it exists, is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws NumberFormatException If the current element has local name <i>name</i> and has text-only content
     *                               that cannot be parsed as a {@link BigDecimal BigDecimal}.
     */
    public BigDecimal getBigDecimalConditional (String name) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? new BigDecimal (s) : null;
      }

    /**
     * Get the text contents of the current {@link Element Element} as a {@link BigInteger BigInteger}.
     * @return The text contents of the current {@link Element Element}, as a {@link BigInteger BigInteger}.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element is empty or a text element that cannot 
     *                               be parsed as a {@link BigInteger BigInteger}.
     */
    public BigInteger getBigInteger () throws NoSuchElementException
      {
        return new BigInteger (getString ());
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as a {@link BigInteger BigInteger}.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element}, as a {@link BigInteger BigInteger}.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element has local name <i>name</i> and is empty or has text-only content
     *                               that cannot be parsed as a {@link BigInteger BigInteger}.
     */
    public BigInteger getBigInteger (String name) throws NoSuchElementException
      {
        return new BigInteger (getString (name));
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>,
     * as a {@link BigInteger BigInteger}.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return The text contents of the current {@link Element Element} as a {@link BigInteger BigInteger},
     *         if it exists, is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws NumberFormatException If the current element has local name <i>name</i> and has text-only content
     *                               that cannot be parsed as a {@link BigInteger BigInteger}.
     */
    public BigInteger getBigIntegerConditional (String name) throws NoSuchElementException
      {
        String s = getStringConditional (name);
        return s != null ? new BigInteger (getStringConditional (name)) : null;
      }

    /*
     * TODO: To be documented.
     */
    public String[] getList () throws NoSuchElementException
      {
        return StringUtil.tokenVector (getString ());
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
    
    /**
     * Get the text contents of the current {@link Element Element}, multiplied by 1000 and truncated, as
     * a <code>long</code>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @return The text contents of the current {@link Element Element} and truncated, 
     *         as a <code>long</code>.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element is empty or a text element that cannot 
     *                               be parsed as a {@link BigDecimal BigDecimal}.
     */
    public long getMoney() throws NoSuchElementException
      {
        return getBigDecimal ().movePointRight (4).longValue ();
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * multiplied by 1000 and truncated, as a <code>long</code>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element} multiplied by 1000 
     *         and truncated, as a <code>long</code>.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws NumberFormatException If the current element has local name <i>name</i> and is empty or has text-only content
     *                               that cannot be parsed as a {@link BigDecimal BigDecimal}.
     */
    public long getMoney (String name) throws NoSuchElementException
      {
        return getBigDecimal (name).movePointRight (4).longValue ();
      }
    
    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>,
     * multiplied by 1000 and truncated, as a <code>long</code>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     * @param name The local element name to test for.
     * @param defaultValue The <code>long</code> value to return if the element does not exist.
     * @return The text contents of the current {@link Element Element} multiplied by 1000
     *         and truncated, as a <code>long</code>, if it exists, is non-empty and has local name <i>name</i>,
     *         <i>defaultValue</i> otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws NumberFormatException If the current element has local name <i>name</i> and has text-only content
     *                               that cannot be parsed as a {@link BigDecimal BigDecimal}.
     */
    public long getMoneyConditional (String name, long defaultValue) throws NoSuchElementException
      {
        BigDecimal t = getBigDecimal (name);
        return t != null ? t.movePointRight (4).longValue () : defaultValue;
      }

    /**
     * Get the <code>Base64</code>-encoded text contents of the current {@link Element Element} as a
     * <code>byte array</code>.
     * @return The <code>Base64</code>-encoded text contents of the current {@link Element Element} as a
     *         <code>byte array</code>.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws IOException If the current element has text-only content
     *                     that cannot be parsed as <code>Base64</code>.
     */
    public byte[] getBinary () throws NoSuchElementException, IOException
      {
        return new Base64 ().getBinaryFromBase64String (getString ());
      }
    
    /**
     * Get the <code>Base64</code>-encoded text contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as a <code>byte array</code>.
     * @param name The local element name expected.
     * @return The <code>Base64</code>-encoded text contents of the current {@link Element Element} as a
     *         <code>byte array</code>.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws IOException If the current element has local name <i>name</i> and has text-only content
     *                     that cannot be parsed as <code>Base64</code>.
     */
    public byte[] getBinary (String name) throws NoSuchElementException, IOException
      {
        return new Base64 ().getBinaryFromBase64String (getString (name));
      }
    
    /**
     * Get the <code>Base64</code>-encoded text contents of the current {@link Element Element}, 
     * if it exists, is non-empty and has local name <i>name</i>, as a <code>byte array</code>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return  The <code>Base64</code>-encoded text contents of the current {@link Element Element} as a
     *         <code>byte array</code>, if it exists, is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws IOException If the current element has local name <i>name</i> and has text-only content
     *                     that cannot be parsed as <code>Base64</code>.
     */
    public byte[] getBinaryConditional (String name) throws NoSuchElementException, IOException
      {
        String s = getStringConditional (name);
        return s != null ? new Base64 ().getBinaryFromBase64String (s) : null;
      }
    

    /**
     * Parse <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code> type:
     * 
     *   _date       = ["-"] 2*C 2Y "-" 2M "-" 2D
     *   _time       = 2h ":" 2m ":" 2s ["." 1*s]
     *   _timeZone   = "Z" / ("+" / "-" 2h ":" 2m)
     *   dateTime    = _date "T" _time [_timeZone]
     */
    public static GregorianCalendar parseDateTime (String s) throws IOException
      {
        GregorianCalendar gc = new GregorianCalendar ();
        gc.clear ();
        
        String t = s;
        int i;

        if(t.startsWith ("-"))
          {
            gc.set (GregorianCalendar.ERA, GregorianCalendar.BC);
            gc.set (GregorianCalendar.YEAR, Integer.parseInt (t.substring (1, i = t.indexOf("-", 1))));
          }
        else
          {
            gc.set (GregorianCalendar.ERA, GregorianCalendar.AD);
            gc.set (GregorianCalendar.YEAR, Integer.parseInt (t.substring (0, i = t.indexOf ("-"))));
          }
        t = t.substring (i+1);

        // Check delimiters (whos positions are now known).
        if (t.charAt(2) != '-' || t.charAt(5) != 'T' ||
            t.charAt(8) != ':' || t.charAt(11) != ':')
          throw new IOException ("Malformed dateTime (" + s + ").");

        gc.set (GregorianCalendar.MONTH, Integer.parseInt (t.substring (0,2)) - 1);
        t = t.substring (3);

        gc.set (GregorianCalendar.DAY_OF_MONTH, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.HOUR_OF_DAY, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.MINUTE, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.SECOND, Integer.parseInt(t.substring (0,2)));
        t = t.substring (2);
            
        // Find time zone info.
        if (t.endsWith ("Z"))
          {
            gc.setTimeZone (TimeZone.getTimeZone("UTC"));
            t = t.substring (0, t.length() - 1);
          }
        else if ((i = t.indexOf ("+")) != -1 || (i = t.indexOf ("-")) != -1)
          {
            if (t.charAt (t.length() - 3) != ':')
              throw new IOException ("Malformed dateTime (" + s + ").");
              
            int tzHour = Integer.parseInt(t.substring (t.charAt(i) == '+' ? i + 1 : i, t.length() - 3)),
                tzMinute = Integer.parseInt(t.substring (t.length() - 2));
            gc.setTimeZone (new SimpleTimeZone (((60 * tzHour) + tzMinute) * 60 * 1000, ""));

            t = t.substring (0, i);
          }
        else
          {
            gc.setTimeZone (TimeZone.getTimeZone("UTC"));
          }

        if (t.length() > 0)
          {
            // Milliseconds.
            if(t.charAt(0) != '.' || t.length () < 2)
              throw new IOException ("Malformed dateTime (" + s + ").");

            t = t.substring (1);

            // We can only handle (exactly) millisecond precision.
            gc.set (GregorianCalendar.MILLISECOND, Integer.parseInt ((t + "000").substring (0, 3)));

            // Round up when necessary.
            if (t.length() > 3 && t.charAt(3) > '4')
              {
                gc.add (GregorianCalendar.MILLISECOND, 1);
              }
          }

        return gc;
      }
    
    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     * contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * <p>Precision will be truncated to milliseconds.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTime () throws NoSuchElementException, IOException
      {
        return parseDateTime (getString ());
      }
    
    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     * contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as a {@link GregorianCalendar GregorianCalendar}.
     * <p>Precision will be truncated to milliseconds.
     * @param name The local element name expected.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTime (String name) throws NoSuchElementException, IOException
      {
        return parseDateTime (getString (name));
      }
    
    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     * contents of the current {@link Element Element}, if it exists, is non-empty and has 
     * local name <i>name</i>, as a {@link GregorianCalendar GregorianCalendar}.
     * <p>Precision will be truncated to milliseconds.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}, 
     *         if it exists, is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>.
     */
    public GregorianCalendar getDateTimeConditional (String name) throws NoSuchElementException, IOException
      {
        String s = getStringConditional (name);
        return s != null ? parseDateTime (s) : null;
      }


      /**
       * Parse <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code> type:
       * 
       *   _date       = ["-"] 2*C 2Y "-" 2M "-" 2D
       */
    public static GregorianCalendar parseDate (String s) throws IOException
      {
          GregorianCalendar gc = new GregorianCalendar();
          gc.clear();
          
          try
          {
              String t = s;
              int i;
              
              if(t.startsWith("-"))
              {
                  gc.set(GregorianCalendar.ERA, GregorianCalendar.BC);
                  gc.set(GregorianCalendar.YEAR, Integer.parseInt(t.substring(1, i = t.indexOf("-", 1))));
              }
              else
              {
                  gc.set(GregorianCalendar.ERA, GregorianCalendar.AD);
                  gc.set(GregorianCalendar.YEAR, Integer.parseInt(t.substring(0, i = t.indexOf("-"))));
              }
              t = t.substring(i+1);
              
              // Check delimiters (whos positions are now known).
              if(t.charAt(2) != '-')
                  throw new IOException("Malformed date (" + s + ").");
              
              gc.set(GregorianCalendar.MONTH, Integer.parseInt(t.substring(0,2)) - 1);
              t = t.substring(3);
              
              gc.set(GregorianCalendar.DAY_OF_MONTH, Integer.parseInt(t.substring(0,2)));
          }
          catch(NumberFormatException nfe)
          {
              throw new IOException("Malformed date (" + s + ").");
          }

          return gc;
      }
      

    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     * contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * @throws NoSuchElementException If the current element has non-text content or
     *                               if there is no current element.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>.
     */
    public GregorianCalendar getDate() throws NoSuchElementException, IOException
      {
        return parseDate (getString ());
      }
    
    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     * contents of the current {@link Element Element}, which must have local name <i>name</i>,
     * as a {@link GregorianCalendar GregorianCalendar}.
     * @param name The local element name expected.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}.
     * @throws NoSuchElementException If the current element has non-text content,
     *                               if it's local name is not <i>name</i> or
     *                               if there is no current element.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>.
     */
    public GregorianCalendar getDate (String name) throws NoSuchElementException, IOException
      {
        return parseDate (getString (name));
      }
    
    /**
     * Get the <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     * contents of the current {@link Element Element}, if it exists, is non-empty and has 
     * local name <i>name</i>, as a {@link GregorianCalendar GregorianCalendar}.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     * @param name The local element name to test for.
     * @return The <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     *         contents of the current {@link Element Element} as a {@link GregorianCalendar GregorianCalendar}, 
     *         if it exists, is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException If the current element has local name <i>name</i> but
     *                               has non-text content.
     * @throws IOException If the current element has text-only content that cannot be parsed as 
     *                     <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>.
     */
    public GregorianCalendar getDateConditional (String name) throws NoSuchElementException, IOException
      {
        String s = getStringConditional (name);
        return s != null ? parseDate (s) : null;
      }

    /* *******************************************************************************
          Debug
       ******************************************************************************* */
    /**
     * Mainly for debugging.
     * <p>Indicates the internal state of this object.
     */
    public String toString ()
      {
        return "DOMReaderHelper (" + __current.getNodeName() + ", " + state + ")";
      }
  }
