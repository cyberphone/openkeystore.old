/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import java.io.IOException;
import java.io.Serializable;

import java.util.Hashtable;
import java.util.Vector;

import java.security.cert.X509Certificate;


public class CertificateLogotypeCache implements Serializable
  {

    private static final long serialVersionUID = 1L;

    private Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> subject_cache = new Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> ();

    private Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> issuer_cache = new Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> ();

    private CertificateLogotype[] getSubjectCertificateLogotypes (X509Certificate certificate, boolean subject) throws IOException
      {
        CertificateLogotypeDescriptor[] descriptors = subject ? 
            CertificateUtil.getSubjectLogotypeDescriptors (certificate) :
            CertificateUtil.getIssuerLogotypeDescriptors (certificate);

        if (descriptors == null)
          {
            return null;
          }

        Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> cache = subject ? subject_cache : issuer_cache;
        Vector<CertificateLogotype> logotypes = new Vector<CertificateLogotype> ();
        for (CertificateLogotypeDescriptor cltd : descriptors)
          {
            if (cltd.isSupported ())
              {
                CertificateLogotype logo = cache.get (cltd);
                if (logo == null)
                  {
                    logo = cltd.getLogotype ();
                    synchronized (this)
                      {
                        cache.put (cltd, logo);
                      }
                  }
                logotypes.add (logo);
              }
          }
        return logotypes.isEmpty () ? null : logotypes.toArray (new CertificateLogotype[0]);
      }


    public CertificateLogotype[] getSubjectLogotypes (X509Certificate certificate) throws IOException
      {
        return getSubjectCertificateLogotypes (certificate, true);
      }


    public CertificateLogotype[] getIssuerLogotypes (X509Certificate certificate) throws IOException
      {
        return getSubjectCertificateLogotypes (certificate, false);
      }

    private void insertLogotype (Hashtable<CertificateLogotypeDescriptor,CertificateLogotype> cache,
                                 CertificateLogotypeDescriptor[] descriptors,
                                 CertificateLogotype logotype) throws IOException
      {
        boolean failed = true;
        for (CertificateLogotypeDescriptor cltd : descriptors)
          {
            if (cltd.isSupported ())
              {
                failed = false;
                cache.put (cltd, logotype);
              }
          }
        if (failed)
          {
            throw new IOException ("No valid descriptors found");
          }
      }

    public void preInitializeSubjectLogotype (X509Certificate certificate, CertificateLogotype certificate_logotype) throws IOException
      {
        insertLogotype (subject_cache, CertificateUtil.getSubjectLogotypeDescriptors (certificate), certificate_logotype);
      }


    public void preInitializeIssuerLogotype (X509Certificate certificate, CertificateLogotype certificate_logotype) throws IOException
      {
        insertLogotype (issuer_cache, CertificateUtil.getIssuerLogotypeDescriptors (certificate), certificate_logotype);
      }

  }
