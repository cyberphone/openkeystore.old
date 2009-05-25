package org.webpki.wasp;

import java.io.IOException;

import java.util.Date;

import org.webpki.crypto.SignerInterface;


public interface SignatureProfileResponseEncoder
  {

    void createSignedData (SignerInterface signer,
                           SignatureResponseEncoder s_resp_enc, 
                           SignatureRequestDecoder s_req_dec,
                           String request_url,
                           Date client_time,
                           byte[] server_certificate_sha1) throws IOException;

  }
