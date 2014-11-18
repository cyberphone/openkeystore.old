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

import java.io.IOException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSignatureWrapper;

public class XMLSignatureResponse  extends XMLObjectWrapper implements XMLEnvelopedInput, BaseProperties
  {
    @Override
    public Document getEnvelopeRoot () throws IOException
      {
        // TODO Auto-generated method stub
        return null;
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
        // TODO Auto-generated method stub
        return null;
      }
  
    @Override
    public XMLSignatureWrapper getSignature () throws IOException
      {
        // TODO Auto-generated method stub
        return null;
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
    protected void fromXML (DOMReaderHelper arg0) throws IOException
      {
        // TODO Auto-generated method stub
        
      }
  
    @Override
    protected boolean hasQualifiedElements ()
      {
        return true;
      }
  
    @Override
    protected void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema ("XMLSignatureResponse.xsd");
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
