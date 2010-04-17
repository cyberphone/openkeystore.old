package org.webpki.keygen2;

import java.io.IOException;

public interface AttestationVerifier
  {
    void verifyAttestation (byte[] attestation, byte[] data) throws IOException;
  }
