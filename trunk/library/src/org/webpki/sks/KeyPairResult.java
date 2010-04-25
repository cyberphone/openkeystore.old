package org.webpki.sks;

import java.security.PublicKey;

public class KeyPairResult
  {
    private PublicKey public_key;
    
    private byte[] key_attestation;
    
    private byte[] encrypted_private_key;
    
    public KeyPairResult (PublicKey public_key, byte[] key_attestation, byte[] encrypted_private_key)
      {
        this.public_key = public_key;
        this.key_attestation = key_attestation;
        this.encrypted_private_key = encrypted_private_key;
      }
    
    public PublicKey getPublicKey ()
      {
        return public_key;
      }
    
    public byte[] getKeyAttestation ()
      {
        return key_attestation;
      }
    
    public byte[] getEncryptedPrivateKey ()
      {
        return encrypted_private_key;
      }

  }
