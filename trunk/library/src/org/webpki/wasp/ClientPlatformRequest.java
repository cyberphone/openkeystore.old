// Implements the WASP "ClientPlatformRequest" XML object

package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLCookie;


public class ClientPlatformRequest
  {

    private Vector<XMLCookie> xml_cookies = new Vector<XMLCookie> ();

    public static final String CLIENT_PLATFORM_REQUEST_ELEM = "ClientPlatformRequest";


    public ClientPlatformRequest addXMLCookie (XMLCookie doc)
      {
        xml_cookies.add (doc);
        return this;
      }


    public ClientPlatformRequest addXMLObjectWrapperCookie (XMLObjectWrapper wrapper) throws IOException
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
        while (rd.hasNext ());
          {
            addXMLCookie (rd.getXMLCookie ());
          }
        rd.getParent ();
      }


    static ClientPlatformRequest read (DOMReaderHelper rd) throws IOException
      {
        ClientPlatformRequest doc_data = new ClientPlatformRequest ();
        rd.getNext (CLIENT_PLATFORM_REQUEST_ELEM);
        doc_data.readXMLCookies (rd);
        return doc_data;
      }


    public void write (DOMWriterHelper wr) throws IOException
      {
        wr.addChildElement (CLIENT_PLATFORM_REQUEST_ELEM);
        for (XMLCookie cookie : xml_cookies)
          {
            wr.addXMLCookie (cookie);
          }
        wr.getParent ();
      }

  }
