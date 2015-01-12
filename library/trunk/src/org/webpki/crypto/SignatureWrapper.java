/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Wrapper over java.security.Signature
 */
public class SignatureWrapper
  {
    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_INTEGER  = 0x02;
    
    static final int LEADING_ZERO  = 0x00;
    
    boolean ecdsa_der_encoded;

    public static byte[] decodeDEREncodedECDSASignature (byte[] der_coded_signature, int extend_to) throws IOException
      {
        int index = 2;
        int length;
        byte[] concatendated_signature = new byte[extend_to << 1];
        if (der_coded_signature[0] != ASN1_SEQUENCE)
          {
            throw new IOException ("Not SEQUENCE");
          }
        length = der_coded_signature[1] & 0xFF;
        if ((length & 0x80) != 0)
          {
            int q = length & 0x7F;
            length = 0;
            while (q-- > 0)
              {
                length <<= 8;
                length += der_coded_signature[index++] & 0xFF;
              }
          }
        for (int offset = 0; offset <= extend_to; offset += extend_to)
          {
            if (der_coded_signature[index++] != ASN1_INTEGER)
              {
                throw new IOException ("Not INTEGER");
              }
            int l = der_coded_signature[index++];
            while (l > extend_to)
              {
                if (der_coded_signature[index++] != LEADING_ZERO)
                  {
                    throw new IOException ("Bad INTEGER");
                  }
                l--;
              }
            System.arraycopy (der_coded_signature, index, concatendated_signature, offset + extend_to - l, l);
            index += l;
          }
        if (index != der_coded_signature.length)
          {
            throw new IOException ("ASN.1 Length error");
          }
        return concatendated_signature;
      }

    public static byte[] encodeDEREncodedECDSASignature (byte[] concatendated_signature, int extend_to) throws IOException
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        for (int offset = 0; offset <= extend_to; offset += extend_to)
          {
            int l = extend_to;
            int start = offset;
            while (concatendated_signature[start] == LEADING_ZERO)
              {
                start++;
                l--;
              }
            boolean add_zero = false;
            if (concatendated_signature[start] < 0)
              {
                add_zero = true;
                l++;
              }
            baos.write (ASN1_INTEGER);
            baos.write (l);
            if (add_zero)
              {
                baos.write (LEADING_ZERO);
              }
            baos.write (concatendated_signature, start, extend_to - start + offset);
          }
        byte[] body = baos.toByteArray ();
        baos = new ByteArrayOutputStream ();
        baos.write (ASN1_SEQUENCE);
        int length = body.length;
        if (length > 127)
          {
            baos.write (0x81);
          }
        baos.write (length);
        baos.write (body);
        return baos.toByteArray ();
      }

    Signature instance;
    boolean rsa_flag;
    int extend_to;

    public SignatureWrapper (AsymSignatureAlgorithms algorithm, PublicKey public_key) throws GeneralSecurityException, IOException
      {
        instance = Signature.getInstance (algorithm.getJCEName ());
        instance.initVerify (public_key);
        rsa_flag = public_key instanceof RSAPublicKey;
        if (!rsa_flag)
          {
            extend_to = (KeyAlgorithms.getECKeyAlgorithm ((ECKey)public_key).getPublicKeySizeInBits () + 7) / 8;
          }
      }

    public SignatureWrapper (AsymSignatureAlgorithms algorithm, PrivateKey private_key) throws GeneralSecurityException, IOException
      {
        instance = Signature.getInstance (algorithm.getJCEName ());
        instance.initSign (private_key);
        rsa_flag = private_key instanceof RSAPrivateKey;
        if (!rsa_flag)
          {
            extend_to = (KeyAlgorithms.getECKeyAlgorithm ((ECKey)private_key).getPublicKeySizeInBits () + 7) / 8;
          }
      }

    public SignatureWrapper setECDSASignatureEncoding (boolean der_encoded)
      {
        ecdsa_der_encoded = der_encoded;
        return this;
      }

    public SignatureWrapper update (byte[] data) throws GeneralSecurityException
      {
        instance.update (data);
        return this;
      }

    public SignatureWrapper update (byte data) throws GeneralSecurityException
      {
        instance.update (data);
        return this;
      }

    public boolean verify (byte[] signature) throws GeneralSecurityException, IOException
      {
        return instance.verify (ecdsa_der_encoded || rsa_flag ?
                                                    signature : SignatureWrapper.encodeDEREncodedECDSASignature (signature,extend_to));
      }

    public byte[] sign () throws GeneralSecurityException, IOException
      {
        return ecdsa_der_encoded || rsa_flag ? 
                            instance.sign () : SignatureWrapper.decodeDEREncodedECDSASignature (instance.sign (), extend_to);
      }
  }
