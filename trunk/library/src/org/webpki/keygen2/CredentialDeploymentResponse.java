// This is the base class which is extended by "CredentialDeploymentResponse" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;


import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class CredentialDeploymentResponse extends XMLObjectWrapper 
  {
    CredentialDeploymentResponse () {}


    public void init () throws IOException
      {
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    public String element ()
      {
        return "CredentialDeploymentResponse";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
