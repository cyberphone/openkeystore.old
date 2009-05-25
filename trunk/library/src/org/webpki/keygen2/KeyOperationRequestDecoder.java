package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Set;
import java.util.GregorianCalendar;
import java.util.EnumSet;

import java.security.cert.X509Certificate;

import org.w3c.dom.Element;

import org.webpki.util.ImageData;
import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.ECCDomains;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyOperationRequestDecoder extends KeyOperationRequest implements Serializable
  {
    private static final long serialVersionUID = 1L;

    class PresetValueReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean hidden;

        Object local_reference_object;

        String name;

        PresetValueReference (DOMReaderHelper rd) throws IOException
          {
            name = rd.getAttributeHelper ().getString (VALUE_REFERENCE_ID_ATTR);
            hidden = rd.getAttributeHelper ().getBooleanConditional (HIDDEN_ATTR);
            preset_value_references.add (this);
          }


        public void setLocalReferenceObject (Object object)
          {
            this.local_reference_object = object;
          }

      }


    public class PresetPIN extends PresetValueReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean user_modifiable;

        PresetPIN (DOMReaderHelper rd) throws IOException
          {
            super (rd);
            user_modifiable = rd.getAttributeHelper ().getBooleanConditional (USER_MODIFIABLE_ATTR);
          }


        public boolean isUserModifiable ()
          {
            return user_modifiable;
          }

      }


    public class PUKPolicy extends PresetValueReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Object user_data;

        PassphraseFormats format;

        int retry_limit;

        PUKPolicy (DOMReaderHelper rd) throws IOException
          {
            super (rd);
            retry_limit = rd.getAttributeHelper ().getInt (RETRY_LIMIT_ATTR);
            format = PassphraseFormats.getPassphraseFormatFromString (rd.getAttributeHelper ().getString (FORMAT_ATTR));
          }


        public int getRetryLimit ()
          {
            return retry_limit;
          }


        public PassphraseFormats getFormat ()
          {
            return format;
          }


        public void setUserData (Object user_data)
          {
            this.user_data = user_data;
          }


        public Object getUserData ()
          {
            return user_data;
          }
      }


    public class PINPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Object user_data;

        PassphraseFormats format;

        int retry_limit;

        int min_length;

        int max_length;

        PINGrouping group;

        boolean caching_support;

        InputMethods input_method;

        Set<PatternRestrictions> pattern_restrictions = EnumSet.noneOf (PatternRestrictions.class);

        PINPolicy (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

            min_length = ah.getInt (MIN_LENGTH_ATTR);

            max_length = ah.getInt (MAX_LENGTH_ATTR);

            if (min_length > max_length)
              {
                bad ("PIN length: min > max");
              }

            retry_limit = ah.getInt (RETRY_LIMIT_ATTR);

            format = PassphraseFormats.getPassphraseFormatFromString (ah.getString (FORMAT_ATTR));

            group = PINGrouping.getPINGroupingFromString (ah.getStringConditional (GROUPING_ATTR,
                                                                                   PINGrouping.NONE.getXMLName ()));

            input_method = InputMethods.getMethodFromString (ah.getStringConditional (INPUT_METHOD_ATTR,
                                                                                      InputMethods.ANY.getXMLName ()));

            caching_support = ah.getBooleanConditional (CACHING_SUPPORT_ATTR);

            String pr[] = ah.getListConditional (PATTERN_RESTRICTIONS_ATTR);
            if (pr != null)
              {
                for (String pattern : pr)
                  {
                    pattern_restrictions.add (PatternRestrictions.getPatternRestrictionFromString (pattern));
                  }
              }
          }


        public PatternRestrictions[] getPatternRestrictions ()
          {
            return pattern_restrictions == null ? null : pattern_restrictions.toArray (new PatternRestrictions[0]);
          }


        public int getMinLength ()
          {
            return min_length;
          }


        public int getMaxLength ()
          {
            return max_length;
          }


        public int getRetryLimit ()
          {
            return retry_limit;
          }


        public PassphraseFormats getFormat ()
          {
            return format;
          }


        public PINGrouping getGrouping ()
          {
            return group;
          }


        public boolean getCachingSupport ()
          {
            return caching_support;
          }


        public InputMethods getInputMethod ()
          {
            return input_method;
          }


        public void setUserData (Object user_data)
          {
            this.user_data = user_data;
          }


        public Object getUserData ()
          {
            return user_data;
          }
      }


    public interface KeyAlgorithmData
      {
      }


    public class RSA implements KeyAlgorithmData, Serializable
      {

        private static final long serialVersionUID = 1L;

        int key_size;

        BigInteger fixed_exponent;  // May be null

        RSA (int key_size, BigInteger fixed_exponent)
          {
            this.key_size = key_size;
            this.fixed_exponent = fixed_exponent;
          }


        public int getKeySize ()
          {
            return key_size;
          }


        public BigInteger getFixedExponent ()
          {
            return fixed_exponent;
          }

      }


    public class ECC implements KeyAlgorithmData, Serializable
      {

        private static final long serialVersionUID = 1L;

        ECCDomains named_curve;

        ECC (ECCDomains named_curve)
          {
            this.named_curve = named_curve;
          }


        public ECCDomains getNamedCurve ()
          {
            return named_curve;
          }

      }


    public interface RequestObjects
      {
      }


    public interface KeyProperties
      {
        public KeyAlgorithmData getKeyAlgorithmData ();

        public KeyGen2KeyUsage getKeyUsage ();

        public boolean isExportable ();

        public String getID ();

      }


    public class CreateKey implements KeyProperties, RequestObjects, Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean start_of_puk_group;

        boolean start_of_pin_group;

        PINPolicy pin_policy;

        PUKPolicy puk_policy;

        PresetPIN preset_pin;

        boolean device_pin_protected;

        String id;

        KeyGen2KeyUsage key_usage;

        KeyAlgorithmData key_algorithm_data;

        boolean exportable;

        X509Certificate archival_key;

        CreateKey (DOMReaderHelper rd, 
                   PINPolicy pin_policy,
                   boolean start_of_pin_group, 
                   PresetPIN preset_pin,
                   boolean device_pin_protected) throws IOException
          {
            this.pin_policy = pin_policy;
            this.start_of_pin_group = start_of_pin_group;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;

            rd.getNext (KEY_PAIR_ELEM);

            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            id = ah.getString (ID_ATTR);
            key_usage = KeyGen2KeyUsage.getKeyUsageFromString (ah.getString (KEY_USAGE_ATTR));
            exportable = ah.getBooleanConditional (EXPORTABLE_ATTR);

            rd.getChild ();

            if (rd.hasNext (RSA_ELEM))
              {
                rd.getNext (RSA_ELEM);

                byte[] exponent = ah.getBinaryConditional (FIXED_EXPONENT_ATTR);
                key_algorithm_data = new RSA (ah.getInt (KEY_SIZE_ATTR),
                                              exponent == null ? null : new BigInteger (exponent));
              }
            else
              {
                rd.getNext (ECC_ELEM);
                key_algorithm_data = new ECC (ECCDomains.getECCDomainFromOID (ah.getString (NAMED_CURVE_ATTR)));
              }
            if (rd.hasNext ())
              {
                rd.getNext (PRIVATE_KEY_ARCHIVAL_KEY_ELEM);
                rd.getChild ();
                archival_key = XMLSignatureWrapper.readSortedX509DataSubset (rd)[0];
                rd.getParent ();
              }

            rd.getParent ();
          }


        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }


        public PUKPolicy getPUKPolicy ()
          {
            return puk_policy;
          }


        public PresetPIN getPresetPIN ()
          {
            return preset_pin;
          }


        public boolean isStartOfPINPolicy ()
          {
            return start_of_pin_group;
          }


        public boolean isStartOfPUKPolicy ()
          {
            return start_of_puk_group;
          }


        public boolean isDevicePINProtected ()
          {
            return device_pin_protected;
          }


        public KeyAlgorithmData getKeyAlgorithmData ()
          {
            return key_algorithm_data;
          }


        public KeyGen2KeyUsage getKeyUsage ()
          {
            return key_usage;
          }


        public boolean isExportable ()
          {
            return exportable;
          }


        public String getID ()
          {
            return id;
          }


        public X509Certificate getPrivateKeyArchivalKey ()
          {
            return archival_key;
          }

      }


    public interface ManageObject
      {
        public X509Certificate getCACertificate ();
      }


    abstract class CAReference implements ManageObject, RequestObjects, Serializable
      {
        private static final long serialVersionUID = 1L;

        X509Certificate ca_certificate;

        private CAReference () {}

        public X509Certificate getCACertificate ()
          {
            return ca_certificate;
          }
      }

    
    public class CertificateReference extends CAReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] certificate_sha1;

        CertificateReference () {}

        CertificateReference (byte[] certificate_sha1)
          {
            this.certificate_sha1 = certificate_sha1;
          }


        public byte[] getCertificateSHA1 () throws IOException
          {
            return certificate_sha1;
          }
      }


    public class DeleteKey extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean conditional;

        DeleteKey (boolean conditional, byte[] certificate_sha1)
          {
            super (certificate_sha1);
            this.conditional = conditional;
          }


        public boolean isConditional ()
          {
            return conditional;
          }
      }


    public class CloneKey extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        CreateKey req_key;

        CloneKey (CreateKey req_key, byte[] certificate_sha1)
          {
            super (certificate_sha1);
            this.req_key = req_key;
          }


        public KeyProperties getCreateKeyProperties ()
          {
            return (KeyProperties) req_key;
          }
      }


    public class ReplaceKey extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        CreateKey req_key;

        ReplaceKey (CreateKey req_key, byte[] certificate_sha1)
          {
            super (certificate_sha1);
            this.req_key = req_key;
          }


        public KeyProperties getCreateKeyProperties ()
          {
            return (KeyProperties) req_key;
          }
      }


    public class DeleteKeysByContent extends CAReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String subject;

        BigInteger serial;

        String email_address;

        String policy;

        GregorianCalendar issued_before;

        GregorianCalendar issued_after;

        String[] excluded_policies;

        DeleteKeysByContent (String subject,
                             BigInteger serial,
                             String email_address,
                             String policy,
                             GregorianCalendar issued_before,
                             GregorianCalendar issued_after,
                             String[] excluded_policies) throws IOException
          {
            if (subject == null && serial == null && email_address == null &&
                policy == null && issued_before == null && issued_after == null &&
                excluded_policies == null)
              {
                bad ("At least one element must be defined for \"DeleteKeysByContent\"");
              }
            this.subject = subject;
            this.serial = serial;
            this.email_address = email_address;
            this.policy = policy;
            this.issued_before = issued_before;
            this.issued_after = issued_after;
            this.excluded_policies = excluded_policies;
          }


        public String getSubject ()
          {
            return subject;
          }


        public BigInteger getSerial ()
          {
            return serial;
          }


        public String getEmailAddress ()
          {
            return email_address;
          }


        public String getPolicy ()
          {
            return policy;
          }


        public GregorianCalendar getIssuedBeforeDate ()
          {
            return issued_before;
          }


        public GregorianCalendar getIssuedAfterDate ()
          {
            return issued_after;
          }


        public String[] getExcludedPolicies ()
          {
            return excluded_policies;
          }
      }


    public class UpdatePINPolicy extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PINPolicy pin_policy;

        boolean force_new_pin;

        UpdatePINPolicy (PINPolicy pin_policy, byte[] certificate_sha1, boolean force_new_pin)
          {
            super (certificate_sha1);
            this.pin_policy = pin_policy;
            this.force_new_pin = force_new_pin;
          }


        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }


        public boolean getForceNewPIN ()
          {
            return force_new_pin;
          }
      }


    public class UpdatePUKPolicy extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PUKPolicy puk_policy;

        UpdatePUKPolicy (PUKPolicy puk_policy, byte[] certificate_sha1)
          {
            super (certificate_sha1);
            this.puk_policy = puk_policy;
          }


        public PUKPolicy getPUKPolicy ()
          {
            return puk_policy;
          }

      }


    public class UpdatePresetPIN extends CertificateReference implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PresetPIN preset_pin;

        UpdatePresetPIN (PresetPIN preset_pin, byte[] certificate_sha1)
          {
            super (certificate_sha1);
            this.preset_pin = preset_pin;
          }


        public PresetPIN getPresetPIN ()
          {
            return preset_pin;
          }

      }


    private class FakeVerifier implements VerifierInterface, Serializable
      {
        private static final long serialVersionUID = 1L;

        X509Certificate certificate;

        public void setTrustedRequired (boolean flag) throws IOException
          {
          }

        public boolean verifyCertificatePath (X509Certificate[] certpath) throws IOException
          {
            certificate = certpath[0];
            return true;
          }

        public X509Certificate[] getSignerCertificatePath () throws IOException
          {
            return null;
          }

        public CertificateInfo getSignerCertificateInfo () throws IOException
          {
            return null;
          }
      }


    private byte[] readSHA1 (DOMAttributeReaderHelper ah) throws IOException
      {
        return ah.getBinary (CERTIFICATE_SHA1_ATTR);
      }


    private void readManageObject (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        Vector<CAReference> kms = new Vector<CAReference> ();
        Element top_elem = rd.getNext (MANAGE_OBJECT_ELEM);
        String id = ah.getString (ID_ATTR);
        if (!ArrayUtil.compare (ah.getBinary (NONCE_ATTR), getSessionHash ()))
          {
            bad ("Nonce error in " + MANAGE_OBJECT_ELEM);
          }
        XMLSignatureWrapper signature = null;
        rd.getChild ();
        do
          {
            if (rd.hasNext (DELETE_KEY_ELEM))
              {
                rd.getNext (DELETE_KEY_ELEM);
                kms.add (new DeleteKey (ah.getBooleanConditional (CONDITIONAL_ATTR, false), readSHA1 (ah)));
              }
            else if (rd.hasNext (CLONE_KEY_ELEM))
              {
                rd.getNext (CLONE_KEY_ELEM);
                byte[] sha1 = readSHA1 (ah);
                rd.getChild ();
                CreateKey rk = new CreateKey (rd, null, false, null, false); 
                rd.getParent ();
                kms.add (new CloneKey (rk, sha1));
              }
            else if (rd.hasNext (REPLACE_KEY_ELEM))
              {
                rd.getNext (REPLACE_KEY_ELEM);
                byte[] sha1 = readSHA1 (ah);
                rd.getChild ();
                CreateKey rk = new CreateKey (rd, null, false, null, false); 
                rd.getParent ();
                kms.add (new ReplaceKey (rk, sha1));
              }
            else if (rd.hasNext (DELETE_KEYS_BY_CONTENT_ELEM))
              {
                rd.getNext (DELETE_KEYS_BY_CONTENT_ELEM);
                kms.add (new DeleteKeysByContent (ah.getStringConditional (SUBJECT_ATTR),
                                                  ah.getBigIntegerConditional (SERIAL_ATTR),
                                                  ah.getStringConditional (EMAIL_ATTR),
                                                  ah.getStringConditional (POLICY_ATTR),
                                                  ah.getDateTimeConditional (ISSUED_BEFORE_ATTR),
                                                  ah.getDateTimeConditional (ISSUED_AFTER_ATTR),
                                                  ah.getListConditional (EXCLUDED_POLICIES_ATTR)));
              }
            else if (rd.hasNext (UPDATE_PIN_POLICY_ELEM))
              {
                rd.getNext (UPDATE_PIN_POLICY_ELEM);
                kms.add (new UpdatePINPolicy (new PINPolicy (rd), readSHA1 (ah), ah.getBooleanConditional (FORCE_NEW_PIN_ATTR)));
              }
            else if (rd.hasNext (UPDATE_PUK_POLICY_ELEM))
              {
                rd.getNext (UPDATE_PUK_POLICY_ELEM);
                kms.add (new UpdatePUKPolicy (new PUKPolicy (rd), readSHA1 (ah)));
              }
            else if (rd.hasNext (UPDATE_PRESET_PIN_ELEM))
              {
                rd.getNext (UPDATE_PRESET_PIN_ELEM);
                kms.add (new UpdatePresetPIN (new PresetPIN (rd), readSHA1 (ah)));
              }
            else
              {
                signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
              }
          }
        while (rd.hasNext ());
        rd.getParent ();
        FakeVerifier fv = new FakeVerifier ();
        new XMLVerifier (fv).validateEnvelopedSignature (this, top_elem, signature, id);
        for (CAReference km : kms)
          {
            km.ca_certificate = fv.certificate;
            request_objects.add (km);
          }
      }


    private void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    private CreateKey readKeyProperties (DOMReaderHelper rd,
                                         PINPolicy pin_policy,
                                         boolean start_of_pin_group) throws IOException
      {
        CreateKey rk;
        if (rd.hasNext (PRESET_PIN_ELEM))
          {
            rd.getNext (PRESET_PIN_ELEM);
            PresetPIN preset = new PresetPIN (rd);
            rd.getChild ();
            request_objects.add (rk = new CreateKey (rd, pin_policy, start_of_pin_group, preset, false));
            rd.getParent ();
          }
        else
          {
            request_objects.add (rk = new CreateKey (rd, pin_policy, start_of_pin_group, null, false));
          }
        return rk;
      }
      

    private void readKeyProperties (DOMReaderHelper rd, boolean device_pin_protected) throws IOException
      {
        request_objects.add (new CreateKey (rd, null, false, null, device_pin_protected));
      }


    private void readPINPolicy (DOMReaderHelper rd, boolean puk_start, PUKPolicy puk_policy) throws IOException
      {
        boolean start = true;
        rd.getNext (PIN_POLICY_ELEM);
        PINPolicy upp = new PINPolicy (rd);
        rd.getChild ();
        do
          {
            CreateKey rk = readKeyProperties (rd, upp, start);
            rk.puk_policy = puk_policy;
            rk.start_of_puk_group = puk_start;
            puk_start = false;
            start = false;
          }
        while (rd.hasNext ());
        rd.getParent ();
      }


    private Vector<RequestObjects> request_objects = new Vector<RequestObjects> ();
      
    private String server_time;

    private String submit_url;

    private ImageData issuer_logotype;      // Optional

    private ServerCookie server_cookie;     // Optional

    private boolean deferred_certification;

    private XMLSignatureWrapper signature;  // Optional

    Vector<PresetValueReference> preset_value_references = new Vector<PresetValueReference> ();

    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public ImageData getIssuerLogotype ()
      {
        return issuer_logotype;
      }


    public String getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public boolean getDeferredCertificationFlag ()
      {
        return deferred_certification;
      }


    public RequestObjects[] getRequestObjects () throws IOException
      {
        return request_objects.toArray (new RequestObjects[0]);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        server_time = ah.getString (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        deferred_certification = ah.getBooleanConditional (DEFERRED_CERTIFICATION_ATTR);

        rd.getChild ();

        if (rd.hasNext (ISSUER_LOGOTYPE_ELEM))
          {
            issuer_logotype = new ImageData (rd.getBinary (ISSUER_LOGOTYPE_ELEM), ah.getString (MIME_TYPE_ATTR));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the request and management elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do
          {
            if (rd.hasNext (MANAGE_OBJECT_ELEM))
              {
                readManageObject (rd);
              }
            else
              {
                rd.getNext (CREATE_OBJECT_ELEM);
                rd.getChild ();
                do
                  {
                    if (rd.hasNext (KEY_PAIR_ELEM))
                      {
                        readKeyProperties (rd, false);
                      }
                    else if (rd.hasNext (PUK_POLICY_ELEM))
                      {
                        boolean start = true;
                        rd.getNext (PUK_POLICY_ELEM);
                        PUKPolicy pk = new PUKPolicy (rd);
                        rd.getChild ();
                        do
                          {
                            readPINPolicy (rd, start, pk);
                            start = false;
                          }
                        while (rd.hasNext ());
                        rd.getParent ();
                      }
                    else if (rd.hasNext (PIN_POLICY_ELEM))
                      {
                        readPINPolicy (rd, false, null);
                      }
                    else
                      {
                        rd.getNext (DEVICE_SYNCHRONIZED_PIN_ELEM);
                        rd.getChild ();
                        readKeyProperties (rd, true);
                        rd.getParent ();
                      }
                  }
                while (rd.hasNext ());
                rd.getParent ();
              }
          }
        while (rd.hasNext (MANAGE_OBJECT_ELEM) || rd.hasNext (CREATE_OBJECT_ELEM));

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ()) // Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }

