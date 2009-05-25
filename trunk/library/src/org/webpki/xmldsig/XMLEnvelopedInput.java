package org.webpki.xmldsig;

import java.io.IOException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;


public interface XMLEnvelopedInput
  {

    Document getEnvelopeRoot () throws IOException;

    String getReferenceURI () throws IOException;

    Element getTargetElem () throws IOException;

    Element getInsertElem () throws IOException; // Sign only

    XMLSignatureWrapper getSignature () throws IOException;  // Verify only

  }
