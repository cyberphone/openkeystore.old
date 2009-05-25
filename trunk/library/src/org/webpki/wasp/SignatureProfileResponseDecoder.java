package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.ServerCookie;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;


public interface SignatureProfileResponseDecoder
  {

    void verifySignature (VerifierInterface verifier) throws IOException;

    boolean match (SignatureProfileEncoder spreenc,
                   DocumentData doc_data,
                   DocumentReferences doc_refs,
                   ServerCookie server_cookie,
                   Vector<CertificateFilter> cert_filters,
                   String id,
                   byte[] expected_sha1) throws IOException;

  }
