package org.webpki.sks;

import java.io.IOException;

import java.security.GeneralSecurityException;

public interface SessionKeyOperations
  {
    public static final byte[] ATTEST_MODIFIER     = new byte[] {'D','e','v','i','c','e',' ','A','t','t','e','s','t','a','t','i','o','n'};

    public static final byte[] SUCCESS_MODIFIER    = new byte[] {'S','u','c','c','e','s','s'};

    public static final byte[] ENCRYPTION_MODIFIER = new byte[] {'E','n','c','r','y','p','t','i','o','n',' ','K','e','y'};

    public static final byte[] SIGNATURE_MODIFIER  = new byte[] {'E','x','t','e','r','n','a','l',' ','S','i','g','n','a','t','u','r','e'};

    public byte[] getMac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException;
    
    public byte[] getAttest (byte[] data) throws IOException, GeneralSecurityException;

  }
