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

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import java.util.regex.Pattern;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import org.webpki.util.ArrayUtil;


public class CertificateFilter
  {
    public static final String CF_FINGER_PRINT          = "FingerPrint";
    public static final String CF_ISSUER_REG_EX         = "IssuerRegEx";
    public static final String CF_SUBJECT_REG_EX        = "SubjectRegEx";
    public static final String CF_EMAIL_REG_EX          = "EmailRegEx";
    public static final String CF_SERIAL_NUMBER         = "SerialNumber";
    public static final String CF_POLICY_RULES          = "PolicyRules";
    public static final String CF_KEY_CONTAINER_LIST    = "KeyContainerList";
    public static final String CF_KEY_USAGE_RULES       = "KeyUsageRules";
    public static final String CF_EXT_KEY_USAGE_RULES   = "ExtKeyUsageRules";

    // Global - Needs path expansion

    private byte[] finger_print;

    private String issuer_reg_ex;

    // Local

    private String subject_reg_ex;

    private String email_reg_ex;

    private String policy_rules;

    private BigInteger serial_number;

    private String key_usage_rules;

    private String ext_key_usage_rules;

    private String key_container_list;

    static final Pattern oid_pattern = Pattern.compile ("[1-9][0-9]*(\\.[1-9][0-9]*)*"); 

    static abstract class BaseRuleParser
      {
        static final char DISALLOWED = '-';
        static final char DELIMITER = ',';
        
        LinkedHashMap<String,Boolean> rules = new LinkedHashMap<String,Boolean> ();

        BaseRuleParser (String rule_string) throws IOException
          {
            if (rule_string != null)
              {
                boolean not_ready = true;
                do
                  {
                    int i = rule_string.indexOf (DELIMITER);
                    if (i < 0)
                      {
                        i = rule_string.length ();
                        not_ready = false;
                      }
                    String rule = rule_string.substring (0, i).trim ();
                    if (not_ready)
                      {
                        rule_string = rule_string.substring (++i);
                      }
                    boolean required = true;
                    if (treatUnspecifiedAsMatching () && rule.charAt (0) == DISALLOWED)
                      {
                        required = false;
                        rule = rule.substring (1);
                      }
                    if (rules.put (parse (rule), required) != null)
                      {
                        throw new IOException ("Duplicate rule: " + rule);
                      }
                  }
                while (not_ready);
              }
          }
        
        String normalized ()
          {
            if (rules.isEmpty ())
              {
                return null;
              }
            StringBuffer nice = new StringBuffer ();
            boolean next = false;
            for (String rule : rules.keySet ())
              {
                if (next)
                  {
                    nice.append (DELIMITER);
                  }
                else
                  {
                    next = true;
                  }
                if (!rules.get (rule))
                  {
                    nice.append (DISALLOWED);
                  }
                nice.append (rule);
              }
            return nice.toString ();
          }
  
        abstract String parse (String argument) throws IOException;

        boolean treatUnspecifiedAsMatching ()
          {
            return true;
          }
        
        boolean checkRule (String rule)
          {
            Boolean required = rules.get (rule);
            if (required != null)
              {
                if (required)
                  {
                    rules.remove (rule);
                  }
                return required;
              }
            return treatUnspecifiedAsMatching ();
          }
  
        boolean gotAllRequired ()
          {
            for (String rule : rules.keySet ())
              {
                if (rules.get (rule))
                  {
                    return false;
                  }
              }
            return true;
          }
      }
  
    static class KeyUsageRuleParser extends BaseRuleParser
      {
        KeyUsageRuleParser (String rule_string) throws IOException
          {
            super (rule_string);
          }
  
        @Override
        String parse (String argument) throws IOException
          {
            return KeyUsageBits.getKeyUsageBit (argument).toString ();
          }
      }
    
    static class OIDRuleParser extends BaseRuleParser
      {
        OIDRuleParser (String rule_string) throws IOException
          {
            super (rule_string);
          }
  
        @Override
        String parse (String argument) throws IOException
          {
            if (!oid_pattern.matcher (argument).matches ())
              {
                throw new IOException ("Bad OID: " + argument);
              }
            return argument;
          }
      }

    static class KeyContainerListParser extends BaseRuleParser
      {
        KeyContainerListParser (String rule_string) throws IOException
          {
            super (rule_string);
          }
  
        @Override
        String parse (String argument) throws IOException
          {
            return KeyContainerTypes.getKeyContainerType (argument).getName ();
          }

        @Override
        boolean treatUnspecifiedAsMatching ()
          {
            return false;
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


    public String getPolicyRules ()
      {
        return policy_rules;
      }


    public BigInteger getSerialNumber ()
      {
        return serial_number;
      }

    public String getKeyContainerList ()
      {
        return key_container_list;
      }


    public String getKeyUsageRules ()
      {
        return key_usage_rules;
      }


    public String getExtKeyUsageRules ()
      {
        return ext_key_usage_rules;
      }



    public CertificateFilter setFingerPrint (byte[] finger_print) throws IOException
      {
        if (finger_print != null && finger_print.length != 32)
          {
            throw new IOException ("\"Sha256\" fingerprint <> 32 bytes!");
          }
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


    public CertificateFilter setPolicyRules (String policy_rules) throws IOException
      {
        this.policy_rules = new OIDRuleParser (policy_rules).normalized ();
        return this;
      }

    public CertificateFilter setSerialNumber (BigInteger serial_number)
      {
        this.serial_number = serial_number;
        return this;
      }

    public CertificateFilter setKeyContainerList (String key_container_list) throws IOException
      {
        this.key_container_list = new KeyContainerListParser (key_container_list).normalized ();
        return this;
      }

    public static LinkedHashSet<KeyContainerTypes> getKeyContainerList (String key_container_list) throws IOException
      {
        KeyContainerListParser parser = new KeyContainerListParser (key_container_list);
        if (parser.rules.isEmpty ())
          {
            return null;
          }
        LinkedHashSet<KeyContainerTypes> containers = new LinkedHashSet<KeyContainerTypes> ();
        for (String container : parser.rules.keySet ())
          {
            containers.add (KeyContainerTypes.getKeyContainerType (container));
          }
        return containers;
      }

    public CertificateFilter setKeyUsageRules (String key_usage_rules) throws IOException
      {
        this.key_usage_rules = new KeyUsageRuleParser (key_usage_rules).normalized ();
        return this;
      }


/**
 * 
 * @param ext_key_usage_rules The argument<br>
 *   <code>&quot;1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4&quot;</code><br>
 *   requires matching end-entity certificates to have exactly two extended key usages,
 *   <code>clientAuthentication</code> and <code>emailProtection</code>
 * @return {@link CertificateFilter}
 * @throws IOException 
 */
    public CertificateFilter setExtendedKeyUsageRules (String ext_key_usage_rules) throws IOException
      {
        this.ext_key_usage_rules = new OIDRuleParser (ext_key_usage_rules).normalized ();
        return this;
      }

    public boolean needsPathExpansion ()
      {
        return finger_print != null || issuer_reg_ex != null;
      }


    public static boolean matchKeyUsage (String specifier, X509Certificate certificate) throws IOException
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
        KeyUsageRuleParser rule_parser = new KeyUsageRuleParser (specifier);
        for (KeyUsageBits ku : KeyUsageBits.values ())
          {
            if (ku.ordinal () < key_usage.length)
              {
                if (key_usage[ku.ordinal()])
                  {
                    if (!rule_parser.checkRule (ku.toString ()))
                      {
                        return false;
                      }
                  }
              }
          }
        return rule_parser.gotAllRequired ();
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
        OIDRuleParser rule_parser = new OIDRuleParser (specifier);
        for (String eku : ekus)
          {
            if (!rule_parser.checkRule (eku))
              {
                return false;
              }
          }
        return rule_parser.gotAllRequired ();
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
        OIDRuleParser rule_parser = new OIDRuleParser (specifier);
        for (String policy : policies)
          {
            if (!rule_parser.checkRule (policy))
              {
                return false;
              }
          }
        return rule_parser.gotAllRequired ();
      }


    private static boolean matchContainers (String specifier, KeyContainerTypes actual) throws IOException
      {
        if (specifier == null)  // no requirement
          {
            return true;
          }
        if (actual == null)  // Requirement but unknown by the client!
          {
            return false;
          }
        KeyContainerListParser rule_parser = new KeyContainerListParser (specifier);
        return rule_parser.checkRule (actual.getName ());
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
                                              KeyContainerTypes key_container) throws IOException
      {
        try
          {
            return matchSerial (serial_number, cert_path[0]) &&
                   matchFingerPrint (finger_print, cert_path) &&
                   matchContainers (key_container_list, key_container) &&
                   matchKeyUsage (key_usage_rules, cert_path[0]) &&
                   matchExtendedKeyUsage (ext_key_usage_rules, cert_path[0]) &&
                   matchPolicy (policy_rules, cert_path[0]) &&
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
