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

import java.io.IOException;
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;

import org.webpki.util.DebugFormatter;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.ASN1BitString;
import org.webpki.asn1.ASN1Sequence;

public class CertificateInfo
  {
    private static final String months[] = {"JAN", "FEB", "MAR", "APR",
                                            "MAY", "JUN", "JUL", "AUG",
                                            "SEP", "OCT", "NOV", "DEC"};

    private String  issuer_dn;
    
    private String  serial_number;
    
    private String  subject_dn;

    private Date    not_valid_before;

    private Date    not_valid_after;

    private X509Certificate  certificate;

    private boolean trusted;

    private boolean trust_mode_set;


    public CertificateInfo (X509Certificate certificate, boolean trusted) throws IOException
      {
        this.certificate = certificate;
        this.trusted = trusted;
        trust_mode_set = true;
        issuer_dn = CertificateUtil.convertRFC2253ToLegacy (certificate.getIssuerX500Principal ().getName ());
        serial_number = certificate.getSerialNumber ().toString ();
        subject_dn = CertificateUtil.convertRFC2253ToLegacy (certificate.getSubjectX500Principal ().getName ());
        not_valid_before = certificate.getNotBefore ();
        not_valid_after = certificate.getNotAfter ();
      }
    
    
    public CertificateInfo (X509Certificate certificate) throws IOException
      {
        this (certificate, true);
        trust_mode_set = false;
      }

   
    private String getItem (String Item)
      {
        return Item == null ? "***UNKNOWN***" : Item;
      }

    private static String toDate (Date t)
      {
        GregorianCalendar c = new GregorianCalendar ();
        c.setTime (t);
        return (c.get (Calendar.DAY_OF_MONTH) < 10 ? "0" : "") + c.get (Calendar.DAY_OF_MONTH) +
               "-" + months[c.get (Calendar.MONTH)] + "-" + String.valueOf (c.get (Calendar.YEAR));
      }


    private void Conditional (StringBuffer sb, String prefix, String attribute)
      {
        if (attribute != null)
          {
            sb.append ("      " + prefix + ": " + attribute + "\n");
          }
      }

    private String getFormattedSubject ()
      {
        StringBuffer sb = new StringBuffer ();
        if (subject_dn != null)
          {
            Conditional (sb, "Name", getSubjectCommonName ());
            Conditional (sb, "SerialNumber", getSubjectSerialNumber ());
            Conditional (sb, "Organization", getSubjectOrganization ());
            Conditional (sb, "Organization Unit", getSubjectOrganizationUnit ());
            Conditional (sb, "Country", getSubjectCountry ());
            Conditional (sb, "e-mail", getSubjectEmail ());
          }
        return sb.toString ();
      }

    private String parseDN (String DNString, String tag)
      {
        if (DNString == null)
          {
            return null;
          }
        StringBuffer sb = new StringBuffer ();
        boolean notfirst = false;
        int i = 0;
        while ((i = DNString.indexOf (tag, i)) >= 0)
          {
            boolean quot = false;
            boolean firstquoted = false;
            boolean lastquoted = false;
            int j = DNString.indexOf ("=", i) + 1;
            int s = j;
            while (j < DNString.length ())
              {
                char ch = DNString.charAt (j);
                if (ch == ',' && !quot)
                  {
                    break;
                  }
                if (ch == '"')
                  {
                    if (s == j)
                      {
                        firstquoted = true;
                      }
                    else
                      {
                        lastquoted = true;
                      }
                    quot = !quot;
                  }
                else
                  {
                    lastquoted = false;
                  }
                j++;
              }
            if (notfirst)
              {
                sb.append (", ");
              }
            notfirst = true;
            if (firstquoted && lastquoted)
              {
                s++;
                --j;
              }
            sb.append (DNString.substring (s, j));
            i = j;
          }
        return notfirst ? sb.toString () : null;
      }


    /*
     * Returns the subject's common name (CN).
     */
    public String getSubjectCommonName ()
      {
        return parseDN (subject_dn, "CN=");
      }


    /*
     * Returns the subject's organization (O).
     */
    public String getSubjectOrganization ()
      {
        return parseDN (subject_dn, "O=");
      }


    /*
     * Returns the subject's organizational unit (OU).
     */
    public String getSubjectOrganizationUnit ()
      {
        return parseDN (subject_dn, "OU=");
      }


    /*
     * Returns the subject's e-mail address (E).
     */
    public String getSubjectEmail ()
      {
        return parseDN (subject_dn, "E=");
      }


    /*
     * Returns the subject's country address (C).
     */
    public String getSubjectCountry ()
      {
        return parseDN (subject_dn, "C=");
      }


    /*
     * Returns the subject's serial number (OID 2.5.4.5).
     */
    public String getSubjectSerialNumber ()
      {
        return parseDN (subject_dn, "SerialNumber=");
      }


    /*
     * Returns the certificate hash.
     */
    public byte[] getCertificateHash ()
      {
        try
          {
            return CertificateUtil.getCertificateSHA1 (certificate);
          }
        catch (IOException ioe)
          {
            return null;
          }
      }


    /*
     * Returns the subject of this certificate
     */
    public String getSubject ()
      {
        return getItem (subject_dn);
      }


    /*
     * Returns the issuer of this certificate
     */
    public String getIssuer ()
      {
        return getItem (issuer_dn);
      }


    /*
     * Returns the serial number of this certificate
     */
    public String getSerialNumber ()
      {
        return getItem (serial_number);
      }


    /*
     * Returns the start date of this certificate's validity period.
     */
    public Date getNotBeforeDate ()
      {
        return not_valid_before;
      }


    /*
     * Returns the end date of this certificate's validity period.
     */
    public Date getNotAfterDate ()
      {
        return not_valid_after;
      }


    /*
     * Checks if this certificate is currently valid.
     */
    public boolean isValid ()
      {
        Date d = new Date();
        return d.after(not_valid_before) && d.before(not_valid_after);
      }


    public String[] getPolicyOIDs () throws IOException
      {
        return CertificateUtil.getPolicyOIDs (certificate);
      }


    public String[] getAIAOCSPResponders () throws IOException
      {
        return CertificateUtil.getAIAOCSPResponders (certificate);
      }


    public String[] getAIACAIssuers () throws IOException
      {
        return CertificateUtil.getAIACAIssuers (certificate);
      }


    public String[] getExtendedKeyUsage () throws IOException
      {
        return CertificateUtil.getExtendedKeyUsage (certificate);
      }


    public String[] getKeyUsages () throws IOException
      {
        return CertificateUtil.getKeyUsages (certificate);
      }


    public String getBasicConstraints ()
      {
        int i = certificate.getBasicConstraints ();
        if (i == -1)
          {
            return "End-entity certificate";
          }
        return "CA certificate, path length constraint: " +
               (i == Integer.MAX_VALUE ? "none" : String.valueOf (i));
      }


    public String getPublicKeyAlgorithm () throws IOException
      {
        return KeyAlgorithms.getKeyAlgorithm (certificate.getPublicKey ()).getAlgorithmId (AlgorithmPreferences.SKS);
      }


    public String getSerialNumberInHex () throws IOException
      {
        return DebugFormatter.getHexString (certificate.getSerialNumber ().toByteArray ());
      }


    public int getPublicKeySize () throws IOException
      {
        return KeyAlgorithms.getKeyAlgorithm (certificate.getPublicKey ()).getPublicKeySizeInBits ();
      }


    public byte[] getCertificateBlob () throws IOException
      {
        try
          {
            return certificate.getEncoded ();
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
      }


    public boolean isTrusted () throws IOException
      {
        if (trust_mode_set)
          {
            return trusted;
          }
        throw new IOException ("Illegal call.  Trust is unknown");
      }


    public byte[] getPublicKeyData () throws IOException
      {
        if (certificate.getPublicKey () instanceof RSAPublicKey)
          {
            return DerDecoder.decode (
                   ((ASN1BitString)(
                      (ASN1Sequence)DerDecoder.decode (
                         certificate.getPublicKey ().getEncoded ())).get(1)).value()).encode ();
          }
        return ParseUtil.bitstring (ParseUtil.sequence(DerDecoder.decode (((ECPublicKey)certificate.getPublicKey ()).getEncoded ()), 2).get (1));
      }


    public String toString (boolean Verbose)
      {
        byte hash[] = getCertificateHash ();
        return "  Subject DN: " + getSubject () + "\n" +
               "  Issuer DN: " + getIssuer () + "\n" +
               "  Serial number: " + getSerialNumber () + "\n" +
               (Verbose ? getFormattedSubject() : "") +
               "  Validity: " + 
                       toDate (not_valid_before) + " To " + 
                       toDate (not_valid_after) + (isValid () ? "" : " ***EXPIRED***") + 
                        (trusted ? "" : " ***UNKNOWN CA***") +
              "\n  SHA1 hash: " + (hash == null ? "BAD" : DebugFormatter.getHexString (hash));
      }


    public String toString ()
      {
        return toString (false);
      }

  }
  
