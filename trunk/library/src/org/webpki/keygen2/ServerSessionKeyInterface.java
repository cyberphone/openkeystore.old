package org.webpki.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import java.util.Date;


public interface ServerSessionKeyInterface
  {
    ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException;
    
    void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                      X509Certificate device_certificate,
                                      String client_session_id,
                                      String server_session_id,
                                      String issuer_uri,
                                      Date client_time,
                                      byte[] session_attestation) throws IOException, GeneralSecurityException;;

    public byte[] mac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException;
    
    public byte[] attest (byte[] data) throws IOException, GeneralSecurityException;
    
    public byte[] encrypt (byte[] data) throws IOException, GeneralSecurityException;

    public byte[] decrypt (byte[] data) throws IOException, GeneralSecurityException;
  }
