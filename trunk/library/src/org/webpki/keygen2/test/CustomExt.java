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
package org.webpki.keygen2.test;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;


public class CustomExt extends XMLObjectWrapper
  {

    public void init () throws IOException
      {
        addSchema ("customext.xsd");
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return "urn:demo:schema";
      }

    
    public String element ()
      {
        return "CustomExt";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        helper.initializeRootObject (null);
        helper.addString ("Data", "Hi there!");
      }

  }
