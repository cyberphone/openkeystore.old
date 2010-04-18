package org.webpki.keygen2;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface MACInterface
  {
    public byte[] getMac (byte[] data, short mac_sequence_counter) throws IOException, GeneralSecurityException;
  }
