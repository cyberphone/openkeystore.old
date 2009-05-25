// Implements the WASP "IdentityProviderAssertions" XML object

package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLCookie;

import static org.webpki.wasp.WASPConstants.*;


public class IdentityProviderAssertions
  {

    private Vector<XMLCookie> xml_cookies = new Vector<XMLCookie> ();


    public IdentityProviderAssertions addXMLCookie (XMLCookie doc)
      {
        xml_cookies.add (doc);
        return this;
      }


    public IdentityProviderAssertions addXMLObjectWrapperCookie (XMLObjectWrapper wrapper) throws IOException
      {
        return addXMLCookie (new XMLCookie (wrapper));
      }


    public XMLCookie[] getXMLCookies () throws IOException
      {
        return xml_cookies.toArray (new XMLCookie[0]);
      }


    private void readXMLCookies (DOMReaderHelper rd) throws IOException
      {
        rd.getChild ();
        do
          {
            addXMLCookie (rd.getXMLCookie ());
          }
        while (rd.hasNext ());
        rd.getParent ();
      }


    public static IdentityProviderAssertions read (DOMReaderHelper rd) throws IOException
      {
        IdentityProviderAssertions doc_data = new IdentityProviderAssertions ();
        rd.getNext (IDP_ASSERTIONS_ELEM);
        doc_data.readXMLCookies (rd);
        return doc_data;
      }


    public Element write (DOMWriterHelper wr, boolean output_ns) throws IOException
      {
        Element elem = output_ns ? wr.addChildElementNS (WASP_NS, IDP_ASSERTIONS_ELEM) : wr.addChildElement (IDP_ASSERTIONS_ELEM);
        if (xml_cookies.isEmpty ())
          {
            throw new IOException ("Missing XMLCookies in IdentityProviderAssertions");
          }
        for (XMLCookie cookie : xml_cookies)
          {
            wr.addXMLCookie (cookie);
          }
        wr.getParent ();
        return elem;
      }


    public Element write (DOMWriterHelper wr) throws IOException
      {
        return write (wr, false);
      }

  }
