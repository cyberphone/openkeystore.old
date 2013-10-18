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


public class CertificateFilter
  {
    // Global - Needs path expansion

    private byte[] finger_print;

    private String issuer_reg_ex;

    // Local

    private String subject_reg_ex;

    private String email_reg_ex;

    private String policy_reg_ex;

    private BigInteger serial_number;

    private KeyUsage key_usage;

    private String ext_key_usage_reg_ex;

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


    private String quote (X500Principal principal)
      {
        return Pattern.quote (principal.getName ());
      }


    private String conditionalCompile (String regex)
      {
        if (regex != null)
          {
            Pattern.compile (regex);
          }
        return regex;
      }


    public byte[] getFingerPrint ()
      {
        return finger_print;
      }


    public String getIssuerRegEx ()
      {
        return issuer_reg_ex;
      }


    public String getSubjectRegEx ()
      {
        return subject_reg_ex;
      }


    public String getEmailRegEx ()
      {
        return email_reg_ex;
      }


    public String getPolicyRegEx ()
      {
        return policy_reg_ex;
      }


    public BigInteger getSerialNumber ()
      {
        return serial_number;
      }

    public KeyContainerTypes[] getContainers ()
      {
        return containers;
      }


    public KeyUsage getKeyUsage ()
      {
        return key_usage;
      }


    public String getExtKeyUsageRegEx ()
      {
        return ext_key_usage_reg_ex;
      }



    public CertificateFilter setFingerPrint (byte[] finger_print)
      {
        this.finger_print = finger_print;
        return this;
      }


    public CertificateFilter setIssuer (X500Principal issuer)
      {
        this.issuer_reg_ex = quote (issuer);
        return this;
      }


    public CertificateFilter setSubject (X500Principal subject)
      {
        this.subject_reg_ex = quote (subject);
        return this;
      }


    public CertificateFilter setIssuerRegEx (String issuer_reg_ex)
      {
        this.issuer_reg_ex = conditionalCompile (issuer_reg_ex);
        return this;
      }


    public CertificateFilter setSubjectRegEx (String subject_reg_ex)
      {
        this.subject_reg_ex = conditionalCompile (subject_reg_ex);
        return this;
      }


    public CertificateFilter setEmail (String email_address)
      {
        this.email_reg_ex = Pattern.quote (email_address);
        return this;
      }


    public CertificateFilter setEmailRegEx (String email_reg_ex)
      {
        this.email_reg_ex = conditionalCompile (email_reg_ex);
        return this;
      }


    public CertificateFilter setPolicyRegEx (String policy_reg_ex)
      {
        this.policy_reg_ex = conditionalCompile (policy_reg_ex);
        return this;
      }

    public CertificateFilter setPolicy (String policy_oid)
      {
        this.policy_reg_ex = Pattern.quote (policy_oid);
        return this;
      }

    public CertificateFilter setSerialNumber (BigInteger serial_number)
      {
        this.serial_number = serial_number;
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
        this.ext_key_usage_reg_ex = Pattern.quote (ext_key_usage_oid);
        return this;
      }

/**
 * 
 * @param ext_key_usage_reg_ex The argument<br>
 *   <code>&quot;1\\.3\\.6\\.1\\.5\\.5\\.7\\.3\\.2|1\\.3\\.6\\.1\\.5\\.5\\.7\\.3\\.4&quot;</code><br>
 *   requires matching end-entity certificates to have exactly two extended key usages,
 *   <code>clientAuthentication</code> and <code>emailProtection</code>
 * @return {@link CertificateFilter}
 */
    public CertificateFilter setExtendedKeyUsageRegEx (String ext_key_usage_reg_ex)
      {
        this.ext_key_usage_reg_ex = conditionalCompile (ext_key_usage_reg_ex);
        return this;
      }

    public boolean needsPathExpansion ()
      {
        return finger_print != null || issuer_reg_ex != null;
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
        String[] ekus = CertificateUtil.getExtendedKeyUsage (certificate);
        if (ekus == null)
          {
            return false;
          }
        Pattern regex = Pattern.compile (specifier);
        for (String eku : ekus)
          {
            if (!regex.matcher (eku).matches ())
              {
                return false;
              }
          }
        return true;
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
        Pattern regex = Pattern.compile (specifier);
        for (String email_address : email_addresses)
          {
            if (regex.matcher (email_address).matches ())
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
        Pattern regex = Pattern.compile (specifier);
        for (String policy_oid : policies)
          {
            if (!regex.matcher (policy_oid).matches ())
              {
                return false;
              }
          }
        return true;
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


    private static boolean matchFingerPrint (byte[] specifier, X509Certificate[] cert_path) throws GeneralSecurityException
      {
        if (specifier == null)
          {
            return true;
          }
        for (X509Certificate certificate : cert_path)
          {
            if (ArrayUtil.compare (specifier,
                                   MessageDigest.getInstance ("SHA256").digest (certificate.getEncoded ())))
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
        if (finger_print != null && finger_print.length != 32)
          {
            throw new IOException ("\"Sha256\" hash not 32 bytes!");
          }
        if (key_usage != null && key_usage.required.isEmpty () && key_usage.disallowed.isEmpty ())
          {
            throw new IOException ("KeyUsage without any specifier is not allowed!");
          }
        try
          {
            return matchSerial (serial_number, cert_path[0]) &&
                   matchFingerPrint (finger_print, cert_path) &&
                   matchContainers (containers, container) &&
                   matchKeyUsage (key_usage == null ? default_key_usage : key_usage, cert_path[0]) &&
                   matchExtendedKeyUsage (ext_key_usage_reg_ex, cert_path[0]) &&
                   matchPolicy (policy_reg_ex, cert_path[0]) &&
                   matchEmailAddress (email_reg_ex, cert_path[0]) &&
                   matchDistinguishedName (issuer_reg_ex, cert_path, true) &&
                   matchDistinguishedName (subject_reg_ex, cert_path, false);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }

  }
