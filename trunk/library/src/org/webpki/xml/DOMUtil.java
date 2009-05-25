package org.webpki.xml;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;

/**
 * Utility methods for traversing and building DOM trees.
 */
public class DOMUtil
  {

    /**
     * Private constructor, no reason to allow instatiation at this time.
     */
    private DOMUtil()
      {
      }
  
    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * @param parent The parent of the new element.
     * @param element The name of the new element.
     * @param value The value of the text node.
     */
    public static Element appendTextElement (Element parent, String element, String value)
      {
        Document d = parent.getOwnerDocument ();
        Element r = d.createElement (element);
        parent.appendChild (r);
        r.appendChild(d.createTextNode (value));
        
        return r;
      }

    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for 
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, Integer.toString(value))</code>
     * @param parent The parent of the new element.
     * @param element The name of the new element.
     * @param value The value of the text node.
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement (Element parent, String element, int value)
      {
        return appendTextElement (parent, element, Integer.toString(value));
      }
    
    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for 
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, Long.toString(value))</code>
     * @param parent The parent of the new element.
     * @param element The name of the new element.
     * @param value The value of the text node.
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement (Element parent, String element, long value)
      {
        return appendTextElement (parent, element, Long.toString (value));
      }
    
    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for 
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, value.toString())</code>
     * and is hence useful when value is an object whos {@link Object#toString toString} function returns a suitably formatted
     * string representation, for example a {@link java.lang.StringBuffer StringBuffer},
     * {@link java.math.BigInteger BigInteger} or {@link java.math.BigDecimal BigDecimal}.
     * @param parent The parent of the new element.
     * @param element The name of the new element.
     * @param value The value of the text node.
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement (Element parent, String element, Object value)
      {
        return appendTextElement (parent, element, value.toString ());
      }
    
    
  
    /**
     * Get the first child {@link org.w3c.dom.Element Element} of an {@link org.w3c.dom.Element Element}.
     * <p>{@link org.w3c.dom.Node Nodes} other than {@link org.w3c.dom.Element Elements} are ignored.
     * @return The first child {@link org.w3c.dom.Element Element} or null if none exists.
     */
    public static Element firstChildElement(Element parent)
      {
        Node n = parent.getFirstChild ();
        
        if (n == null || n instanceof Element)
          {
            return (Element)n;
          }
        else
          {
            return nextSiblingElement (n);
          }
      }
    
    /**
     * Get the next sibling {@link org.w3c.dom.Element Element} of a {@link org.w3c.dom.Node Node}.
     * <p>{@link org.w3c.dom.Node Nodes} other than {@link org.w3c.dom.Element Elements} are ignored.
     * @return The first child {@link org.w3c.dom.Element Element} or null if none exists.
     */
    public static Element nextSiblingElement (Node n)
      {
        do
          {
            if ((n = n.getNextSibling()) == null)
              {
                return null;
              }
          }
        while (!(n instanceof Element));
        
        return (Element)n;
      }

      
    /**
     * Gets the sibling Element with the indicated name. The sibling
     * searched for must come after the given Element e.
     * 
     * @param e Element to start search from.
     * @param name Name to search for in sibling.
     * @return The sibling Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static Element getSiblingElement (Element e, String name)
      {
        Element elem = e;
  
        /* 
         * Loop until we find the correct element or until we run 
         * out of siblings. 
         */
        while ((elem = nextSiblingElement(elem)) != null) 
          {
            if (elem.getNodeName ().equals (name)) 
              {
                return elem;
              }
          }
    
        return null;
      }


    /**
     * Gets the value for the sibling Element with the indicated name. The sibling
     * searched for must come after the given Element e.
     * 
     * @param e Element to start search from.
     * @param name Name to search for in sibling.
     * @return The value of the sibling Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static String getSiblingValue (Element e, String name) 
      {
        Element elem = e;

        /* 
         * Loop until we find the correct element or until we run 
         * out of siblings. 
         */
        while ((elem = nextSiblingElement (elem)) != null) 
          {
              if (elem.getNodeName ().equals (name)) 
                {
                  return elem.getFirstChild ().getNodeValue ();
                }
          }
    
        return null;
      }


    /**
     * Gets the child Element with the indicated name. The child
     * searched for must exist one level below the parent, i.e. a real 
     * parent-child relation.
     * 
     * @param parent Parent Element to start search from.
     * @param name Name to search for in child.
     * @return The child Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static Element getChildElement (Element parent, String name) 
      {
        Element elem;

        if ((elem = firstChildElement (parent)) == null) 
          {
            return null;
          }

        /* Check first child. */
        if (elem.getNodeName ().equals (name)) 
          {
            return elem;
          }

        /* Loop the rest. */
        while ((elem = nextSiblingElement (elem)) != null) 
          {
            if (elem.getNodeName ().equals (name)) 
              {
                return elem;
              }
          }
    
        return null;
      }

    /**
     * Gets the value for the child Element with the indicated name. The child
     * searched for must exist one level below the parent, i.e. a real 
     * parent-child relation.
     * 
     * @param parent Parent Element to start search from.
     * @param name Name to search for in child.
     * @return The value for the child Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static String getChildElementValue (Element parent, String name)
      {
        Element elem;

        if ((elem = firstChildElement (parent)) == null) 
          {
            return null;
          }

        /* Check first child. */
        if (elem.getNodeName ().equals (name)) 
          {
            return elem.getFirstChild ().getNodeValue ();
          }

        /* Loop the rest. */
        while ((elem = nextSiblingElement (elem)) != null)
          {
            if (elem.getNodeName ().equals (name))
              {
                return elem.getFirstChild ().getNodeValue ();
              }
          }
          
        return null;
      }
    
    /**
     * Get the target namespace corresponding to a prefix.
     */
    public static String getNamespace (Element e, String prefix)
      {
        String nsURI = null;
        Node n;
        
        while ((nsURI = e.getAttribute (prefix != null ? "xmlns:" + prefix : "xmlns")) == null &&
               (n = e.getParentNode ()) != null && n instanceof Element)
          {
            e = (Element)n;
          }
        
        return nsURI;
      }

    /**
     * 
     */
    private static String emptyAsNull (String s)
      {
        return s != null && s.length () != 0 ? s : null;
      }
    
    /**
     * Get the defining target namespace of this element 
     */
    public static String getDefiningNamespace (Element e)
      {
//        return e.lookupNamespaceURI (e.getPrefix ());
        String prefix = getPrefix (e);

        String nsURI = null, noNSPrefix = null, noNSURI = null;
        Node n = e;

        do
          {
            e = (Element)n;

            nsURI = emptyAsNull (e.getAttribute (prefix != null ? "xmlns:" + prefix : "xmlns"));
            
            if (noNSPrefix == null)
              {
                noNSPrefix = getPrefix (e);
              }
            
            if (noNSPrefix != null && noNSURI == null)
              {
                noNSURI = emptyAsNull (e.getAttribute ("xmlns:" + noNSPrefix));
              }
          }
        while ((n = e.getParentNode()) != null && n instanceof Element && nsURI == null);
        // TODO: Should noNSURI == null also be in the loop condition <=>
        //       can default namespace reach inside nodes of other namespaces?
        
        return (prefix != null || nsURI != null) ? nsURI : noNSURI;
     }
    
    /**
     * Write the XML-encoding of a {@link Document Document} to an 
     * {@link java.io.OutputStream OutputStream}.
     */
    public static void writeXML (Document d, OutputStream out) throws IOException
      {
        OutputFormat format = new OutputFormat (d);
        format.setPreserveSpace (true);
        XMLSerializer serial = new XMLSerializer (out, format);
        serial.asDOMSerializer ();
        serial.serialize (d.getDocumentElement ());
      }

    public static void writeXML (Element e, OutputStream out) throws IOException
      {
        OutputFormat format = new OutputFormat (e.getOwnerDocument ());
        format.setPreserveSpace (true);
        XMLSerializer serial = new XMLSerializer (out, format);
        serial.asDOMSerializer ();
        serial.serialize (e);
      }

    /**
     * Write the XML-encoding of a {@link Document Document} to a byte array.
     */
    public static byte[] writeXML(Document d) throws IOException
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        writeXML (d, baos);
        baos.close ();
        return baos.toByteArray ();
      }
    
    public static byte[] writeXML(Element e) throws IOException
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        writeXML (e, baos);
        baos.close ();
        return baos.toByteArray ();
      }
    
    
    /**
     * Write the &quot;pretty printed&quot; XML-encoding of a {@link Document Document}
     * to an {@link java.io.OutputStream OutputStream}.
     */
    public static void writePrettyXML (Document d, OutputStream out, int indent, int lineWidth)
    throws IOException
      {
        OutputFormat format = new OutputFormat (d);
        format.setIndenting (true);
        format.setIndent (indent);
        format.setLineWidth (lineWidth);
        XMLSerializer serial = new XMLSerializer (out, format);
        serial.asDOMSerializer ();
        serial.serialize (d.getDocumentElement ());
      }

    /**
     * Write the &quot;pretty printed&quot;XML-encoding of a {@link Document Document}
     * to a byte array.
     */
    public static byte[] writePrettyXML (Document d, int indent, int lineWidth) throws IOException
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        writePrettyXML (d, baos, indent, lineWidth);
        baos.close ();
        return baos.toByteArray ();
      }
    
    
    public static String getPrefix (Node n)
      {
        String s = n.getNodeName ();
        int i = s.indexOf (':');
        return i < 0 ? null : s.substring (0, i);
      }
    
    public static String getLocalName (Node n)
      {
        String s = n.getNodeName ();
        int i = s.indexOf (':');
        return i < 0 ? s : s.substring (i + 1);
      }
    
    public static boolean booleanValue (String s)
      {
        if (s.equals ("true") || s.equals ("1"))
          {
            return true;
          }
        else if (s.equals ("false") || s.equals ("0"))
          {
            return false;
          }
        else
          {
            throw new IllegalArgumentException ("Not an XML boolean: " + s);
          }
      }
    
  }
