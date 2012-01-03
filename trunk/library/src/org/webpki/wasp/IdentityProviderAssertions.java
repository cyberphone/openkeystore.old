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
package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLCookie;

import static org.webpki.wasp.WASPConstants.*;

/**
 * Implements the WASP "IdentityProviderAssertions" XML object
 *
 */
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
