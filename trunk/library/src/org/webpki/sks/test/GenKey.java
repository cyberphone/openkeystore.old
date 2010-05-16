/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.test;

import java.io.IOException;
import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.GregorianCalendar;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.test.DemoKeyStore;

public class GenKey
  {
    String id;
    int key_handle;
    PublicKey public_key;
    X509Certificate[] cert_path;
    ProvSess prov_sess;
    
    public GenKey setCertificate (String dn) throws IOException, GeneralSecurityException
      {
        CertSpec cert_spec = new CertSpec ();
        cert_spec.setEndEntityConstraint ();
        cert_spec.setSubject (dn);

        GregorianCalendar start = new GregorianCalendar ();
        GregorianCalendar end = (GregorianCalendar) start.clone ();
        end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);
    
        X509Certificate certificate = 
            new CA ().createCert (cert_spec,
                                  DistinguishedName.subjectDN ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")),
                                  new BigInteger (String.valueOf (new Date ().getTime ())),
                                  start.getTime (),
                                  end.getTime (), 
                                  SignatureAlgorithms.RSA_SHA256,
                                  new AsymKeySignerInterface ()
            {
    
              @Override
              public PublicKey getPublicKey () throws IOException, GeneralSecurityException
                {
                  return ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")).getPublicKey ();
                }
    
              @Override
              public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException, GeneralSecurityException
                {
                  Signature signer = Signature.getInstance (algorithm.getJCEName ());
                  signer.initSign ((PrivateKey) DemoKeyStore.getSubCAKeyStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
                  signer.update (data);
                  return signer.sign ();
                }
              
            }, public_key);
        return setCertificate (new X509Certificate[]{certificate});
      }
    
    public GenKey setCertificate (X509Certificate[] cert_path) throws IOException, GeneralSecurityException
      {
        this.cert_path = cert_path;
        prov_sess.setCertificate (key_handle, id, public_key, cert_path);
        return this;
      }
        
  }
