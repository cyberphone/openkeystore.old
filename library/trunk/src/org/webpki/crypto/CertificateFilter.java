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

import java.math.BigInteger;

import java.util.Set;
import java.util.EnumSet;

import java.util.regex.Pattern;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;


public class CertificateFilter
  {
    // Global - Needs path expansion

    private byte[] sha1;

    private String issuer_regex;

    // Local

    private String subject_regex;

    private String email_address;

    private String policy_oid;

    private BigInteger serial;

    private KeyUsage key_usage;

    private String ext_key_usage_oid;

    private KeyContainerTypes[] containers;


    public static class KeyUsage
      {
        Set<KeyUsageBits> required = EnumSet.noneOf (KeyUsageBits.class);

        Set<KeyUsageBits> disallowed = EnumSet.noneOf (KeyUsageBits.class);

        private void test_for_ambiguity (Set<KeyUsageBits> currset, KeyUsageBits key_usage) throws IOException
          {
            if (currset.contains (key_usage))
              {
                throw new IOException ("Ambigious key usage setting for bit: " + key_usage);
              }
          } 


        public KeyUsage disAllow (KeyUsageBits key_usage) throws IOException
          {
            test_for_ambiguity (required, key_usage);
            disallowed.add (key_usage);
            return this;
          }


        public KeyUsage require (KeyUsageBits key_usage) throws IOException
          {
            test_for_ambiguity (disallowed, key_usage);
            required.add (key_usage);
            return this;
          }


        public Set<KeyUsageBits> getDisAllowedBits ()
          {
            return disallowed;
          }


        public Set<KeyUsageBits> getRequiredBits ()
          {
            return required;
          }
      }


    private String quote (String dn_verbatim)
      {
        return Pattern.quote (CertificateUtil.convertLegacyToRFC2253 (dn_verbatim));
      }


    private String multiple (String[] dn_verbatim)
      {
        if (dn_verbatim.length <= 1)
          {
            return quote (dn_verbatim[0]);
          }
        StringBuffer s = new StringBuffer ('(');
        for (int i = 0; i < dn_verbatim.length; i++)
          {
            if (i > 0)
              {
                s.append ('|');
              }
            s.append (quote (dn_verbatim[i]));
          }
        return s.append (')').toString ();
      }


    private String compile (String dn_expression)
      {
        if (dn_expression == null)
          {
            return null;
          }
        Pattern.compile (dn_expression);
        return dn_expression;
      }


    public byte[] getSha1 ()
      {
        return sha1;
      }


    public String getIssuerRegEx ()
      {
        return issuer_regex;
      }


    public String getSubjectRegEx ()
      {
        return subject_regex;
      }


    public String getEmailAddress ()
      {
        return email_address;
      }


    public String getPolicy ()
      {
        return policy_oid;
      }


    public BigInteger getSerial ()
      {
        return serial;
      }

    public KeyContainerTypes[] getContainers ()
      {
        return containers;
      }


    public KeyUsage getKeyUsage ()
      {
        return key_usage;
      }


    public String getExtKeyUsage ()
      {
        return ext_key_usage_oid;
      }



    public CertificateFilter setSha1 (byte[] sha1)
      {
        this.sha1 = sha1;
        return this;
      }


    public CertificateFilter setSha1 (String sha1_in_hex) throws IOException
      {
        return setSha1 (DebugFormatter.getByteArrayFromHex (sha1_in_hex));
      }


    public CertificateFilter setIssuerDN (String dn_verbatim)
      {
        this.issuer_regex = quote (dn_verbatim);
        return this;
      }


    public CertificateFilter setIssuerDN (String[] dn_verbatim)
      {
        this.issuer_regex = multiple (dn_verbatim);
        return this;
      }


    public CertificateFilter setSubjectDN (String dn_verbatim)
      {
        this.subject_regex = quote (dn_verbatim);
        return this;
      }


    public CertificateFilter setSubjectDN (String[] dn_verbatim)
      {
        this.subject_regex = multiple (dn_verbatim);
        return this;
      }


    public CertificateFilter setIssuerRegEx (String dn_expression)
      {
        this.issuer_regex = compile (dn_expression);
        return this;
      }


    public CertificateFilter setSubjectRegEx (String dn_expression)
      {
        this.subject_regex = compile (dn_expression);
        return this;
      }


    public CertificateFilter setEmailAddress (String email_address)
      {
        this.email_address = email_address;
        return this;
      }


    public CertificateFilter setPolicy (String policy_oid)
      {
        this.policy_oid = policy_oid;
        return this;
      }


    public CertificateFilter setSerial (BigInteger serial)
      {
        this.serial = serial;
        return this;
      }

    public CertificateFilter setContainers (KeyContainerTypes[] containers)
      {
        this.containers = containers;
        return this;
      }


    public CertificateFilter setKeyUsage (KeyUsage key_usage)
      {
        this.key_usage = key_usage;
        return this;
      }


    public CertificateFilter setExtendedKeyUsage (String ext_key_usage_oid)
      {
        this.ext_key_usage_oid = ext_key_usage_oid;
        return this;
      }


    public boolean needsPathExpansion ()
      {
        return sha1 != null || issuer_regex != null;
      }


    public static boolean matchKeyUsage (KeyUsage specifier, X509Certificate certificate) throws IOException
      {
        if (specifier == null)
          {
            return true;
          }
        boolean[] key_usage = certificate.getKeyUsage ();
        if (key_usage == null)
          {
            return false;
          }
        for (KeyUsageBits ku : specifier.required)
          {
            if (ku.ordinal () < key_usage.length)
              {
                if (!key_usage[ku.ordinal()])
                  {
                    return false;
                  }
              }
            else
              {
                return false;
              }
          }
        for (KeyUsageBits ku : specifier.disallowed)
          {
            if (ku.ordinal () < key_usage.length)
              {
                if (key_usage[ku.ordinal()])
                  {
                    return false;
                  }
              }
          }
        return true;
      }


    private static boolean matchExtendedKeyUsage (String specifier, X509Certificate certificate) throws IOException
      {
        if (specifier == null)
          {
            return true;
          }
        String[] eku = CertificateUtil.getExtendedKeyUsage (certificate);
        if (eku == null)
          {
            return false;
          }
        for (String oid : eku)
          {
            if (oid.equals (specifier))
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchEmailAddress (String specifier, X509Certificate certificate) throws IOException
      {
        if (specifier == null)
          {
            return true;
          }
        String[] email_addresses = CertificateUtil.getSubjectEmailAddresses (certificate);
        if (email_addresses == null)
          {
            return false;
          }
        for (String email_address : email_addresses)
          {
            if (specifier.equals (email_address))
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchPolicy (String specifier, X509Certificate certificate) throws IOException
      {
        if (specifier == null)
          {
            return true;
          }
        String[] policies = CertificateUtil.getPolicyOIDs (certificate);
        if (policies == null)
          {
            return false;
          }
        for (String policy_oid : policies)
          {
            if (specifier.equals (policy_oid))
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchContainers (KeyContainerTypes[] specifier, KeyContainerTypes actual)
      {
        if (specifier == null)  // no requirement
          {
            return true;
          }
        if (actual == null)  // Requirement but unknown by the client!
          {
            return false;
          }
        for (KeyContainerTypes container : specifier)
          {
            if (actual == container)
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchDistinguishedName (String specifier, X509Certificate[] cert_path, boolean issuer)
      {
        if (specifier == null)
          {
            return true;
          }
        Pattern pattern = Pattern.compile (specifier);
        int path_len = issuer ? cert_path.length : 1;
        for (int q = 0; q < path_len; q++)
          {
            String dn = issuer ? cert_path[q].getIssuerX500Principal ().getName (X500Principal.RFC2253)
                                         :
                                 cert_path[q].getSubjectX500Principal ().getName (X500Principal.RFC2253);
            if (pattern.matcher (dn).matches ())
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchSha1 (byte[] specifier, X509Certificate[] cert_path) throws GeneralSecurityException
      {
        if (specifier == null)
          {
            return true;
          }
        for (X509Certificate certificate : cert_path)
          {
            if (ArrayUtil.compare (specifier,
                                   MessageDigest.getInstance ("SHA1").digest (certificate.getEncoded ())))
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchSerial (BigInteger specifier, X509Certificate certificate)
      {
        if (specifier == null)
          {
            return true;
          }
        return specifier.equals (certificate.getSerialNumber ());
      }


    public boolean matches (X509Certificate[] cert_path,
                                              KeyUsage default_key_usage,
                                              KeyContainerTypes container) throws IOException
      {
        if (sha1 != null && sha1.length != 20)
          {
            throw new IOException ("\"Sha1\" hash not 20 bytes!");
          }
        if (key_usage != null && key_usage.required.isEmpty () && key_usage.disallowed.isEmpty ())
          {
            throw new IOException ("KeyUsage without any specifier is not allowed!");
          }
        try
          {
            return matchSerial (serial, cert_path[0]) &&
                   matchSha1 (sha1, cert_path) &&
                   matchContainers (containers, container) &&
                   matchKeyUsage (key_usage == null ? default_key_usage : key_usage, cert_path[0]) &&
                   matchExtendedKeyUsage (ext_key_usage_oid, cert_path[0]) &&
                   matchPolicy (policy_oid, cert_path[0]) &&
                   matchEmailAddress (email_address, cert_path[0]) &&
                   matchDistinguishedName (issuer_regex, cert_path, true) &&
                   matchDistinguishedName (subject_regex, cert_path, false);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }

  }
