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

import java.security.interfaces.RSAPublicKey;

/**
 * Wrapper over java.security.Signature
 */
public class SignatureWrapper
  {
    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_INTEGER  = 0x02;
    
    static final int LEADING_ZERO   = 0x00;
    
    boolean ecdsa_der_encoded;

    public static byte[] decode (byte[] der_coded_signature, PublicKey public_key) throws IOException
      {
        if (public_key instanceof RSAPublicKey)
          {
            return der_coded_signature;
          }
        int index = 2;
        int length;
        int extend_to = (KeyAlgorithms.getKeyAlgorithm (public_key).getPublicKeySizeInBits () + 7) / 8;
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

    public static byte[] encode (byte[] concatendated_signature, PublicKey public_key) throws IOException
      {
        if (public_key instanceof RSAPublicKey)
          {
            return concatendated_signature;
          }
        int extend_to = (KeyAlgorithms.getKeyAlgorithm (public_key).getPublicKeySizeInBits () + 7) / 8;
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
    PublicKey public_key;

    public SignatureWrapper (AsymSignatureAlgorithms algorithm, PublicKey public_key) throws GeneralSecurityException
      {
        instance = Signature.getInstance (algorithm.getJCEName ());
        this.public_key = public_key;
      }
    public SignatureWrapper setECDSASignatureEncoding (boolean der_encoded)
      {
        ecdsa_der_encoded = der_encoded;
        return this;
      }

    public SignatureWrapper initVerify () throws GeneralSecurityException
      {
        instance.initVerify (public_key);
        return this;
      }

    public SignatureWrapper initSign (PrivateKey private_key) throws GeneralSecurityException
      {
        instance.initSign (private_key);
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
        return instance.verify (ecdsa_der_encoded ? signature : SignatureWrapper.encode (signature, public_key));
      }

    public byte[] sign () throws GeneralSecurityException, IOException
      {
        return ecdsa_der_encoded ? instance.sign () : SignatureWrapper.decode (instance.sign (), public_key);
      }
  }
