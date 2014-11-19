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
package org.webpki.webapps.wcppsignaturedemo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSignatureWrapper;

public class XMLSignatureResponse  extends XMLObjectWrapper implements XMLEnvelopedInput, BaseProperties
  {
    XMLSignatureWrapper signature;
    String id;
    
    static String schema =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +

      "<xs:schema targetNamespace=\"" + WCPP_DEMO_CONTEXT_URI + "\" " +
                 "xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" " +
                 "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " +
                 "xmlns=\"" + WCPP_DEMO_CONTEXT_URI + "\" " +
                 "elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

         "<xs:import namespace=\"http://www.w3.org/2000/09/xmldsig#\"/>" +

         "<xs:element name=\"" + Messages.SIGNATURE_RESPONSE.toString () + "\">" +
            "<xs:complexType>" +
               "<xs:sequence>" +
                  "<xs:element name=\"" + REQUEST_DATA_JSON + "\">" +
                     "<xs:complexType>" +
                        "<xs:attribute name=\"" + DATE_TIME_JSON + "\" type=\"xs:dateTime\" use=\"required\"/>" +
                        "<xs:attribute name=\"" + ORIGIN_JSON + "\" type=\"xs:anyURI\" use=\"required\"/>" +
                        "<xs:attribute name=\"" + REFERENCE_ID_JSON + "\" type=\"xs:string\" use=\"required\"/>" +
                     "</xs:complexType>" +
                  "</xs:element>" +
                  "<xs:element name=\"" + DOCUMENT_DATA_JSON + "\">" +
                  "<xs:complexType>" +
                     "<xs:choice>" +
                        "<xs:element name=\"" + DOCUMENT_JSON + "\" type=\"xs:base64Binary\"/>" +
                        "<xs:element name=\"" + DOCUMENT_HASH_JSON + "\">" +
                           "<xs:complexType>" +
                              "<xs:attribute name=\"" + ALGORITHM_JSON + "\" type=\"xs:anyURI\" use=\"required\"/>" +
                              "<xs:attribute name=\"" + VALUE_JSON + "\" type=\"xs:base64Binary\" use=\"required\"/>" +
                           "</xs:complexType>" +
                        "</xs:element>" +
                     "</xs:choice>" +
                     "<xs:attribute name=\"" + MIME_TYPE_JSON + "\" type=\"xs:string\" use=\"required\"/>" +
                  "</xs:complexType>" +
               "</xs:element>" +
                  "<xs:element ref=\"ds:" + XMLSignatureWrapper.SIGNATURE_ELEM + "\"/>" +
               "</xs:sequence>" +
               "<xs:attribute name=\"" + DATE_TIME_JSON + "\" type=\"xs:dateTime\" use=\"required\"/>" +
               "<xs:attribute name=\"" + XMLSignatureWrapper.ID_ATTR + "\" type=\"xs:ID\" use=\"required\"/>" +
            "</xs:complexType>" +
         "</xs:element>" +
       
      "</xs:schema>";

    @Override
    public Document getEnvelopeRoot () throws IOException
      {
        return getRootDocument ();
      }
  
    @Override
    public Element getInsertElem () throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }
  
    @Override
    public String getReferenceURI () throws IOException
      {
         return id;
      }
  
    @Override
    public XMLSignatureWrapper getSignature () throws IOException
      {
        return signature;
      }
  
    @Override
    public Element getTargetElem () throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }
  
    @Override
    public String element ()
      {
        return Messages.SIGNATURE_RESPONSE.toString ();
      }
  
    @Override
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        id = ah.getString (XMLSignatureWrapper.ID_ATTR);
        rd.getChild ();
        rd.getNext (REQUEST_DATA_JSON);
        rd.getNext (DOCUMENT_DATA_JSON);
        signature = (XMLSignatureWrapper) wrap (rd.getNext ());
      }
  
    @Override
    protected boolean hasQualifiedElements ()
      {
        return true;
      }
  
    @Override
    protected InputStream getResource (String name) throws IOException
      {
        return new ByteArrayInputStream (schema.getBytes ("UTF-8"));
      }

    @Override
    protected void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema ("dummy");  // see getResource()
      }
  
    @Override
    public String namespace ()
      {
        return WCPP_DEMO_CONTEXT_URI;
      }
  
    @Override
    protected void toXML (DOMWriterHelper arg0) throws IOException
      {
        // TODO Auto-generated method stub
        
      }
  }
