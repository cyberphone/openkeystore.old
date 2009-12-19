package org.webpki.crypto;

import java.io.IOException;

import java.security.cert.X509Certificate;


/**
 * PKI signature interface.
 * Note that the actual key, certificate path, and signature creation mechanism are supposed to
 * be hosted by the implementing class.
 */
public interface SignerInterface
  {

    /**
     * Returns the certificate path associated with the key.
     */
    public X509Certificate[] prepareSigning (boolean fullpath) throws IOException;

    /**
     * Signs data using the key.
     */
    public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException;

    /**
     * Returns a descriptor of the signer certificate.
     */
    public CertificateInfo getSignerCertificateInfo () throws IOException;
    
    /**
     * Tests if a signature operation failed due to authorization errors.
     * 
     * @return true if the key wasn't authorized (wrong PIN)
     * @throws IOException
     */
    public boolean authorizationFailed () throws IOException;

  }
