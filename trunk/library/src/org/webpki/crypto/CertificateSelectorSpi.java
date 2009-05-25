package org.webpki.crypto;

import java.io.IOException;


public interface CertificateSelectorSpi
  {

    /**
     * Filters PKI certificates.  This method is primarily designed for on-line signature and
     * authentication where they relying party provides a filter scheme such as with TLS.
     */
    CertificateSelection getCertificateSelection (CertificateFilter[] cfs, 
                                                  CertificateFilter.KeyUsage default_key_usage) throws IOException;

  }
