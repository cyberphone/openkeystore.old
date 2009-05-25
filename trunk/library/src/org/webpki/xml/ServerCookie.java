// Implements an inline "ServerCookie" XML object used by KeyGen2, WASP, and WebAuth

package org.webpki.xml;

import java.io.IOException;
import java.io.Serializable;

import java.util.Vector;

import org.w3c.dom.Element;


public class ServerCookie implements Serializable
  {
    private static final long serialVersionUID = 1L;

    public static final String SERVER_COOKIE_ELEM = "ServerCookie";

    private Vector<XMLCookie> xml_cookies = new Vector<XMLCookie> ();


    public ServerCookie addXMLCookie (XMLCookie doc)
      {
        xml_cookies.add (doc);
        return this;
      }


    public ServerCookie addXMLObjectWrapperCookie (XMLObjectWrapper wrapper) throws IOException
      {
        return addXMLCookie (new XMLCookie (wrapper));
      }


    public XMLCookie[] getXMLCookies () throws IOException
      {
        return xml_cookies.toArray (new XMLCookie[0]);
      }


    public static ServerCookie read (DOMReaderHelper rd) throws IOException
      {
        ServerCookie doc_data = new ServerCookie ();
        rd.getNext (SERVER_COOKIE_ELEM);
        rd.getChild ();
        do
          {
            doc_data.addXMLCookie (rd.getXMLCookie ());
          }
        while (rd.hasNext ());
        rd.getParent ();
        return doc_data;
      }


    public Element write (DOMWriterHelper wr, String output_ns) throws IOException
      {
        Element elem = output_ns == null ? wr.addChildElement (SERVER_COOKIE_ELEM) : wr.addChildElementNS (output_ns, SERVER_COOKIE_ELEM);
        if (xml_cookies.isEmpty ())
          {
            throw new IOException ("Missing XMLCookies in ServerCookie");
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
        return write (wr, null);
      }


    public boolean equals (ServerCookie ref) throws IOException
      {
        if (xml_cookies.size () != ref.xml_cookies.size ())
          {
            return false;
          }
        int i = 0;
        for (XMLCookie cookie : xml_cookies)
          {
            if (!cookie.equals (ref.xml_cookies.elementAt (i++)))
              {
                return false;
              }
          }
        return true;
      }

  }
