/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.android.crypto;

import java.io.IOException;

import java.math.BigInteger;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import java.util.regex.Pattern;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import org.webpki.android.util.ArrayUtil;


public class CertificateFilter
  {
    public static final String CF_FINGER_PRINT          = "FingerPrint";
    public static final String CF_ISSUER_REG_EX         = "IssuerRegEx";
    public static final String CF_SERIAL_NUMBER         = "SerialNumber";
    public static final String CF_SUBJECT_REG_EX        = "SubjectRegEx";
    public static final String CF_EMAIL_REG_EX          = "EmailRegEx";
    public static final String CF_POLICY_RULES          = "PolicyRules";
    public static final String CF_KEY_USAGE_RULES       = "KeyUsageRules";
    public static final String CF_EXT_KEY_USAGE_RULES   = "ExtendedKeyUsageRules";

    // Global - Needs path expansion

    byte[] finger_print;

    String issuer_reg_ex;

    // Local

    String subject_reg_ex;

    String email_reg_ex;

    String[] policy_rules;

    BigInteger serial_number;

    String[] key_usage_rules;

    String[] extended_key_usage_rules;

    static final Pattern oid_pattern = Pattern.compile ("[1-9][0-9]*(\\.[1-9][0-9]*)*"); 

    static final char DISALLOWED = '-';

    static abstract class BaseRuleParser
      {
        LinkedHashMap<String,Boolean> rules = new LinkedHashMap<String,Boolean> ();

        BaseRuleParser (String[] rule_set) throws IOException
          {
            if (rule_set != null)
              {
                if (rule_set.length == 0)
                  {
                    throw new IOException ("Empty list not allowed");
                  }
                for (String rule : rule_set)
                  {
                    boolean required = true;
                    if (rule.charAt (0) == DISALLOWED)
                      {
                        required = false;
                        rule = rule.substring (1);
                      }
                    if (rules.put (parse (rule), required) != null)
                      {
                        throw new IOException ("Duplicate rule: " + rule);
                      }
                  }
              }
          }
        
        String[] normalized ()
          {
            if (rules.isEmpty ())
              {
                return null;
              }
            LinkedHashSet<String> rule_set = new LinkedHashSet<String> ();
            for (String rule : rules.keySet ())
              {
                rule_set.add (rules.get (rule) ? rule : DISALLOWED + rule);
              }
            return rule_set.toArray (new String[0]);
          }
  
        abstract String parse (String argument) throws IOException;

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
            return true;
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
        KeyUsageRuleParser (String[] rule_set) throws IOException
          {
            super (rule_set);
          }
  
        @Override
        String parse (String argument) throws IOException
          {
            return KeyUsageBits.getKeyUsageBit (argument).getX509Name ();
          }
      }
    
    static class OIDRuleParser extends BaseRuleParser
      {
        OIDRuleParser (String[] rule_set) throws IOException
          {
            super (rule_set);
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

    protected void nullCheck (Object o) throws IOException
      {
        
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


    public String[] getPolicyRules ()
      {
        return policy_rules;
      }


    public BigInteger getSerialNumber ()
      {
        return serial_number;
      }


    public String[] getKeyUsageRules ()
      {
        return key_usage_rules;
      }


    public String[] getExtendedKeyUsageRules ()
      {
        return extended_key_usage_rules;
      }



    public CertificateFilter setFingerPrint (byte[] finger_print) throws IOException
      {
        nullCheck (finger_print);
        if (finger_print != null && finger_print.length != 32)
          {
            throw new IOException ("\"Sha256\" fingerprint <> 32 bytes!");
          }
        this.finger_print = finger_print;
        return this;
      }


    public CertificateFilter setIssuer (X500Principal issuer) throws IOException
      {
        nullCheck (issuer);
        this.issuer_reg_ex = quote (issuer);
        return this;
      }


    public CertificateFilter setSubject (X500Principal subject) throws IOException
      {
        nullCheck (subject);
        this.subject_reg_ex = quote (subject);
        return this;
      }


    public CertificateFilter setIssuerRegEx (String issuer_reg_ex) throws IOException
      {
        nullCheck (issuer_reg_ex);
        this.issuer_reg_ex = conditionalCompile (issuer_reg_ex);
        return this;
      }


    public CertificateFilter setSubjectRegEx (String subject_reg_ex) throws IOException
      {
        nullCheck (subject_reg_ex);
        this.subject_reg_ex = conditionalCompile (subject_reg_ex);
        return this;
      }


    public CertificateFilter setEmail (String email_address) throws IOException
      {
        nullCheck (email_address);
        this.email_reg_ex = Pattern.quote (email_address);
        return this;
      }


    public CertificateFilter setEmailRegEx (String email_reg_ex) throws IOException
      {
        nullCheck (email_reg_ex);
        this.email_reg_ex = conditionalCompile (email_reg_ex);
        return this;
      }


    public CertificateFilter setPolicyRules (String[] rule_set) throws IOException
      {
        nullCheck (rule_set);
        this.policy_rules = new OIDRuleParser (rule_set).normalized ();
        return this;
      }

    public CertificateFilter setSerialNumber (BigInteger serial_number) throws IOException
      {
        nullCheck (serial_number);
        this.serial_number = serial_number;
        return this;
      }

    public CertificateFilter setKeyUsageRules (String[] key_usage_rules) throws IOException
      {
        nullCheck (key_usage_rules);
        this.key_usage_rules = new KeyUsageRuleParser (key_usage_rules).normalized ();
        return this;
      }

    public CertificateFilter setKeyUsageRules (KeyUsageBits[] required, KeyUsageBits[] disallowed) throws IOException
      {
        nullCheck (required);
        nullCheck (disallowed);
        Vector<String> list = new Vector<String> ();
        for (KeyUsageBits kub : required)
          {
            list.add (kub.getX509Name ());
          }
        for (KeyUsageBits kub : disallowed)
          {
            list.add (DISALLOWED + kub.getX509Name ());
          }
        this.key_usage_rules = new KeyUsageRuleParser (list.toArray (new String[0])).normalized ();
        return this;
      }

/**
 * 
 * @param extended_key_usage_rules The argument<br>
 *   <code>&quot;new String[]{"1.3.6.1.5.5.7.3.2","1.3.6.1.5.5.7.3.4"}&quot;</code><br>
 *   requires matching end-entity certificates to have (at least) the two extended key usages,
 *   <code>clientAuthentication</code> and <code>emailProtection</code>
 * @return {@link CertificateFilter}
 * @throws IOException 
 */
    public CertificateFilter setExtendedKeyUsageRules (String[] extended_key_usage_rules) throws IOException
      {
        nullCheck (extended_key_usage_rules);
        this.extended_key_usage_rules = new OIDRuleParser (extended_key_usage_rules).normalized ();
        return this;
      }

    public boolean needsPathExpansion ()
      {
        return finger_print != null || issuer_reg_ex != null;
      }


    public static boolean matchKeyUsage (String[] specifier, X509Certificate certificate) throws IOException
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
        for (KeyUsageBits kub : KeyUsageBits.values ())
          {
            if (kub.ordinal () < key_usage.length)
              {
                if (key_usage[kub.ordinal()])
                  {
                    if (!rule_parser.checkRule (kub.getX509Name ()))
                      {
                        return false;
                      }
                  }
              }
          }
        return rule_parser.gotAllRequired ();
      }


    private static boolean matchExtendedKeyUsage (String[] specifier, X509Certificate certificate) throws IOException
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


    private static boolean matchPolicy (String specifier[], X509Certificate certificate) throws IOException
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


    private static boolean matchDistinguishedName (String specifier, X509Certificate[] certificate_path, boolean issuer)
      {
        if (specifier == null)
          {
            return true;
          }
        Pattern pattern = Pattern.compile (specifier);
        int path_len = issuer ? certificate_path.length : 1;
        for (int q = 0; q < path_len; q++)
          {
            String dn = issuer ? certificate_path[q].getIssuerX500Principal ().getName (X500Principal.RFC2253)
                                         :
                                 certificate_path[q].getSubjectX500Principal ().getName (X500Principal.RFC2253);
            if (pattern.matcher (dn).matches ())
              {
                return true;
              }
          }
        return false;
      }


    private static boolean matchFingerPrint (byte[] specifier, X509Certificate[] certificate_path) throws GeneralSecurityException
      {
        if (specifier == null)
          {
            return true;
          }
        for (X509Certificate certificate : certificate_path)
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


    public boolean matches (X509Certificate[] certificate_path) throws IOException
      {
        try
          {
            return matchSerial (serial_number, certificate_path[0]) &&
                   matchFingerPrint (finger_print, certificate_path) &&
                   matchKeyUsage (key_usage_rules, certificate_path[0]) &&
                   matchExtendedKeyUsage (extended_key_usage_rules, certificate_path[0]) &&
                   matchPolicy (policy_rules, certificate_path[0]) &&
                   matchEmailAddress (email_reg_ex, certificate_path[0]) &&
                   matchDistinguishedName (issuer_reg_ex, certificate_path, true) &&
                   matchDistinguishedName (subject_reg_ex, certificate_path, false);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  }
