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
package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLCookie;

/**
 * Implements the WASP "ClientPlatformRequest" XML object
 * 
 */
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
