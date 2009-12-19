package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Date;
import java.util.TreeMap;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECCDomains;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyOperationRequestEncoder extends KeyOperationRequest implements Serializable
  {
    private static final long serialVersionUID = 1L;

    class PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String value;

        byte[] encrypted_value;

        String name;

        PresetValue (String value) throws IOException
          {
            this.value = value;
            name = "Value." + next_personal_code++;
            preset_values.add (this);
          }

        boolean hidden;

        void write (DOMWriterHelper wr) throws IOException
          {
            if (hidden)
              {
                wr.setBooleanAttribute (HIDDEN_ATTR, hidden);
              }
            wr.setStringAttribute (VALUE_REFERENCE_ID_ATTR, name);
          }
      }


    private class PresetPIN extends PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean user_modifiable;

        PresetPIN (String value, boolean hidden, boolean user_modifiable) throws IOException
          {
            super (value);
            this.hidden = hidden;
            this.user_modifiable = user_modifiable;
          }

        void writePINValue (DOMWriterHelper wr) throws IOException
          {
            super.write (wr);
            if (user_modifiable)
              {
                wr.setBooleanAttribute (USER_MODIFIABLE_ATTR, user_modifiable);
              }
          }
      }


    public class PUKPolicy extends PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean written;

        PassphraseFormats format;

        int retry_limit;

        PUKPolicy (String value, PassphraseFormats format, int retry_limit, boolean hidden) throws IOException
          {
            super (value);
            super.hidden = hidden;
            this.format = format;
            this.retry_limit = retry_limit;
          }


        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            super.write (wr);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());
          }
      }


    public class PINPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean written;

        boolean not_first;

        String preset_test;

        // Actual data

        PassphraseFormats format;

        int min_length;

        int max_length;

        int retry_limit;

        PINGrouping group;  // Optional

        PatternRestrictions[] pattern_restrictions; // Optional

        boolean caching_support;  // Optional

        InputMethods input_method;  // Optional

        private PINPolicy () {}

        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            wr.setIntAttribute (MAX_LENGTH_ATTR, max_length);
            wr.setIntAttribute (MIN_LENGTH_ATTR, min_length);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            if (group != null)
              {
                wr.setStringAttribute (GROUPING_ATTR, group.getXMLName ());
              }
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());
            if (pattern_restrictions != null)
              {
                Vector<String> prs = new Vector<String> ();
                for (PatternRestrictions pr : pattern_restrictions)
                  {
                    prs.add (pr.getXMLName ());
                  }
                wr.setListAttribute (PATTERN_RESTRICTIONS_ATTR, prs.toArray (new String[0]));
              }
            if (caching_support)
              {
                wr.setBooleanAttribute (CACHING_SUPPORT_ATTR, caching_support);
              }
            if (input_method != null)
              {
                wr.setStringAttribute (INPUT_METHOD_ATTR, input_method.getXMLName ());
              }
          }


        public PINPolicy setInputMethod (InputMethods input_method)
          {
            this.input_method = input_method;
            return this;
          }


        public PINPolicy setGrouping (PINGrouping group)
          {
            this.group = group;
            return this;
          }


        public PINPolicy setCachingSupport (boolean flag)
          {
            this.caching_support = flag;
            return this;
          }


        public PINPolicy setPatternRestrictions (PatternRestrictions[] patterns)
          {
            this.pattern_restrictions = patterns;
            return this;
          }

      }


    public static abstract class KeyAlgorithmData implements Serializable
      {
        private static final long serialVersionUID = 1L;

        abstract void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException;

        private KeyAlgorithmData () {}

        public static final class ECC extends KeyAlgorithmData implements Serializable
          {

            private static final long serialVersionUID = 1L;

            ECCDomains named_curve;

            @SuppressWarnings("unused")
            private ECC () {}

            public ECC (ECCDomains named_curve)
              {
                this.named_curve = named_curve;
              }


            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                wr.addChildElement (ECC_ELEM);
                wr.setStringAttribute (NAMED_CURVE_ATTR, named_curve.getOID ());
                wr.getParent ();
              }
          }


        public static final class RSA extends KeyAlgorithmData implements Serializable
          {

            private static final long serialVersionUID = 1L;

            int key_size;

            BigInteger fixed_exponent;

            @SuppressWarnings("unused")
            private RSA () {}


            public RSA (int key_size)
              {
                this.key_size = key_size;
              }


            public RSA (int key_size, BigInteger fixed_exponent)
              {
                this (key_size);
                this.fixed_exponent = fixed_exponent;
              }


            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                wr.addChildElement (RSA_ELEM);
                wr.setIntAttribute (KEY_SIZE_ATTR, key_size);
                if (fixed_exponent != null)
                  {
                    wr.setBinaryAttribute (FIXED_EXPONENT_ATTR, fixed_exponent.toByteArray ());
                  }
                wr.getParent ();
              }
          }


        public static final class DSA extends KeyAlgorithmData implements Serializable
          {
            private static final long serialVersionUID = 1L;

            int key_size;

            @SuppressWarnings("unused")
            private DSA () {}

            public DSA (int key_size)
              {
                this.key_size = key_size;
              }


            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                bad ("DSA not implemented!");
              }
          }

      }


    private abstract class ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        X509Certificate certificate;

        KeyOperationRequestEncoder key_gen_req_enc;

        abstract void write (DOMWriterHelper wr) throws IOException;

        void writeCert (DOMWriterHelper wr) throws IOException
          {
            wr.setBinaryAttribute (CERTIFICATE_SHA1_ATTR, CertificateUtil.getCertificateSHA1 (certificate));
          }

        ManageObjectOperation (X509Certificate certificate)
          {
            this.certificate = certificate;
          }
      }


    private class DeleteKey extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean conditional;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (DELETE_KEY_ELEM);
            if (conditional)
              {
                wr.setBooleanAttribute (CONDITIONAL_ATTR, conditional);
              }
            writeCert (wr);
            wr.getParent ();
          }

        DeleteKey (X509Certificate certificate, boolean conditional)
          {
            super (certificate);
            this.conditional = conditional;
          }
      }


    public class DeleteKeysByContent extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String subject;

        BigInteger serial;

        String email_address;

        String policy;

        Date issued_before;

        Date issued_after;

        String[] excluded_policies;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (DELETE_KEYS_BY_CONTENT_ELEM);
            if (subject == null && serial == null && email_address == null &&
                policy == null && issued_before == null && issued_after == null &&
                excluded_policies == null)
              {
                bad ("At least one element must be defined for \"DeleteKeysByContent\"");
              }

            if (subject != null)
              {
                wr.setStringAttribute (SUBJECT_ATTR, subject);
              }

            if (serial != null)
              {
                wr.setBigIntegerAttribute (SERIAL_ATTR, serial);
              }

            if (email_address != null)
              {
                wr.setStringAttribute (EMAIL_ATTR, email_address);
              }

            if (policy != null)
              {
                wr.setStringAttribute (POLICY_ATTR, policy);
              }

            if (issued_before != null)
              {
                wr.setDateTimeAttribute (ISSUED_BEFORE_ATTR, issued_before);
              }

            if (issued_after != null)
              {
                wr.setDateTimeAttribute (ISSUED_AFTER_ATTR, issued_after);
              }

            if (excluded_policies != null)
              {
                wr.setListAttribute (EXCLUDED_POLICIES_ATTR, excluded_policies);
              }

            wr.getParent ();
          }

        DeleteKeysByContent ()
          {
            super (null);
          }


        public DeleteKeysByContent setSubject (String subject)
          {
            this.subject = subject;
            return this;
          }


        public DeleteKeysByContent setSerial (BigInteger serial)
          {
            this.serial = serial;
            return this;
          }


        public DeleteKeysByContent setEmailAddress (String address)
          {
            this.email_address = address;
            return this;
          }


        public DeleteKeysByContent setPolicy (String policy)
          {
            this.policy = policy;
            return this;
          }


        public DeleteKeysByContent setExcludedPolicies (String[] policies)
          {
            this.excluded_policies = policies;
            return this;
          }


        public DeleteKeysByContent setIssuedBeforeDate (Date date)
          {
            this.issued_before = date;
            return this;
          }


        public DeleteKeysByContent setIssuedAfterDate (Date date)
          {
            this.issued_after = date;
            return this;
          }

      }


    private class CloneKey extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        KeyProperties requested_key;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (CLONE_KEY_ELEM);
            writeCert (wr);
            requested_key.writeRequest (wr);
            wr.getParent ();
          }

        CloneKey (X509Certificate certificate, KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data) throws IOException
          {
            super (certificate);
            requested_key = new KeyProperties (key_usage, key_alg_data, null, null, null, false);
          }
      }


    private class ReplaceKey extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        KeyProperties requested_key;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (REPLACE_KEY_ELEM);
            writeCert (wr);
            requested_key.writeRequest (wr);
            wr.getParent ();
          }

        ReplaceKey (X509Certificate certificate, KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data) throws IOException
          {
            super (certificate);
            requested_key = new KeyProperties (key_usage, key_alg_data, null, null, null, false);
          }
      }


    private class UpdatePINPolicy extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PINPolicy pin_policy;

        boolean force_new_pin;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (UPDATE_PIN_POLICY_ELEM);
            writeCert (wr);
            pin_policy.writePolicy (wr);
            if (force_new_pin)
              {
                wr.setBooleanAttribute (FORCE_NEW_PIN_ATTR, force_new_pin);
              }
            wr.getParent ();
          }

        UpdatePINPolicy (X509Certificate certificate, PINPolicy pin_policy, boolean force_new_pin) throws IOException
          {
            super (certificate);
            this.pin_policy = pin_policy;
            this.force_new_pin = force_new_pin;
          }
      }


    private class UpdatePUKPolicy extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PUKPolicy puk_policy;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (UPDATE_PUK_POLICY_ELEM);
            writeCert (wr);
            puk_policy.writePolicy (wr);
            wr.getParent ();
          }

        UpdatePUKPolicy (X509Certificate certificate, PUKPolicy puk_policy) throws IOException
          {
            super (certificate);
            this.puk_policy = puk_policy;
          }
      }


    private class UpdatePresetPIN extends ManageObjectOperation implements Serializable
      {
        private static final long serialVersionUID = 1L;

        PresetPIN preset_pin;

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (UPDATE_PRESET_PIN_ELEM);
            writeCert (wr);
            preset_pin.writePINValue (wr);
            wr.getParent ();
          }

        UpdatePresetPIN (X509Certificate certificate, PresetPIN preset_pin) throws IOException
          {
            super (certificate);
            this.preset_pin = preset_pin;
          }
      }


    public class ManageObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String id;

        Vector<ManageObjectOperation> manage_objects = new Vector<ManageObjectOperation> ();

        KeyOperationRequestEncoder key_gen_req_enc;

        boolean signed;

        OutputManageObject omo = new OutputManageObject ();

        private class OutputManageObject extends XMLObjectWrapper implements XMLEnvelopedInput, Serializable
          {
            private static final long serialVersionUID = 1L;

            public String getReferenceURI ()
              {
                return id; 
              }


            public Element getInsertElem ()
              {
                return null;
              }


            public XMLSignatureWrapper getSignature ()
              {
                return null;
              }


            protected void toXML (DOMWriterHelper wr) throws IOException
              {
                wr.initializeRootObject (prefix);

                wr.setStringAttribute (ID_ATTR, id);
                wr.setBinaryAttribute (NONCE_ATTR, getSessionHash ());

                for (ManageObjectOperation kmo : manage_objects)
                  {
                    kmo.write (wr);
                  }
              }


            public void init () throws IOException
              {
              }


            public Document getEnvelopeRoot () throws IOException
              {
                return getRootDocument ();
              }


            public Element getTargetElem () throws IOException
              {
                return null;
              }


            protected boolean hasQualifiedElements ()
              {
                return true;
              }


            public String namespace ()
              {
                return KEYGEN2_NS;
              }

    
            public String element ()
              {
                return MANAGE_OBJECT_ELEM;
              }


            protected void fromXML (DOMReaderHelper helper) throws IOException
              {
                bad ("Should have been implemented in derived class");
              }

           }


        private XMLObjectWrapper getOutputManageObect ()
          {
            return omo;
          }


        private ManageObject () {}


        public void signManageObject (SignerInterface signer_interface) throws IOException
          {
            if (signed)
              {
                bad ("ManageObject is already signed!");
              }
            if (manage_objects.isEmpty ())
              {
                bad ("Empty ManageObject!");
              }
            omo.forcedDOMRewrite ();
            XMLSigner signer = new XMLSigner (signer_interface);
            signer.removeXMLSignatureNS ();
            signer.createEnvelopedSignature (omo);
            omo.getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
            signed = true;
          }


        private void addKMOp (ManageObjectOperation kmo) throws IOException
          {
            kmo.key_gen_req_enc = key_gen_req_enc;
            if (signed)
              {
                bad ("You cannot add key management operations after signing!");
              }
            manage_objects.add (kmo);
          }


        public void deleteKey (X509Certificate certificate, boolean conditional) throws IOException
          {
            addKMOp (new DeleteKey (certificate, conditional));
          }


        public KeyProperties cloneKey (X509Certificate certificate,
                                       KeyGen2KeyUsage key_usage,
                                       KeyAlgorithmData key_alg_data) throws IOException
          {
            CloneKey ck = new CloneKey (certificate, key_usage, key_alg_data);
            addKMOp (ck);
            return ck.requested_key;
          }


        public KeyProperties replaceKey (X509Certificate certificate,
                                         KeyGen2KeyUsage key_usage,
                                         KeyAlgorithmData key_alg_data) throws IOException
          {
            ReplaceKey rk = new ReplaceKey (certificate, key_usage, key_alg_data);
            addKMOp (rk);
            return rk.requested_key;
          }


        public DeleteKeysByContent deleteKeysByContent () throws IOException
          {
            DeleteKeysByContent dkbc = new DeleteKeysByContent ();
            addKMOp (dkbc);
            return dkbc;
          }


        public void updatePINPolicy (X509Certificate certificate,
                                    PINPolicy pin_policy,
                                    boolean force_new_pin) throws IOException
          {
            addKMOp (new UpdatePINPolicy (certificate, pin_policy, force_new_pin));
          }


        public void updatePUKPolicy (X509Certificate certificate,
                                     PUKPolicy puk_policy) throws IOException
          {
            addKMOp (new UpdatePUKPolicy (certificate, puk_policy));
          }


        public void updatePresetPIN (X509Certificate certificate,
                                     String pin_value, boolean hidden, boolean user_modifiable) throws IOException
          {
            addKMOp (new UpdatePresetPIN (certificate, new PresetPIN (pin_value, hidden, user_modifiable)));
          }

      }


    public class KeyProperties implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean exportable;
 
        public KeyProperties setExportable (boolean flag)
          {
            exportable = flag;
            return this;
          }


        String id;

        public String getID ()
          {
            return id;
          }


        KeyGen2KeyUsage key_usage;

        public KeyGen2KeyUsage getKeyUsage ()
          {
            return key_usage;
          }


        X509Certificate archival_key;

        public void setPrivateKeyArchivalKey (X509Certificate archival_key) throws IOException
          {
            this.archival_key = archival_key;
            if (key_usage != KeyGen2KeyUsage.ENCRYPTION)
              {
                bad ("Key archival is only permitted for encryption keys!");
              }
          }


        KeyAlgorithmData key_alg_data;

        PINPolicy pin_policy;

        PUKPolicy puk_policy;

        PresetPIN preset_pin;

        boolean device_pin_protected;

        KeyProperties (KeyGen2KeyUsage key_usage,
                       KeyAlgorithmData key_alg_data,
                       PINPolicy pin_policy,
                       PUKPolicy puk_policy,
                       PresetPIN preset_pin,
                       boolean device_pin_protected) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.key_usage = key_usage;
            this.key_alg_data = key_alg_data;
            this.pin_policy = pin_policy;
            this.puk_policy = puk_policy;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;
            if (pin_policy != null)
              {
                if (pin_policy.not_first)
                  {
                    if (pin_policy.group == PINGrouping.SHARED &&
                        ((pin_policy.preset_test == null && preset_pin != null) ||
                         (pin_policy.preset_test != null && preset_pin == null) ||
                         (pin_policy.preset_test != null && preset_pin != null &&
                             !preset_pin.value.equals (pin_policy.preset_test))))
                      {
                        bad ("\"shared\" PIN keys must either have no \"preset_pin\" " +
                             "value or the same value for each requested key");
                      }
                  }
                else
                  {
                    pin_policy.not_first = true;
                    pin_policy.preset_test = preset_pin == null ? null : preset_pin.value;
                  }
              }
          }

        void writeRequest (DOMWriterHelper wr) throws IOException
          {
            if (device_pin_protected)
              {
                wr.addChildElement (DEVICE_SYNCHRONIZED_PIN_ELEM);
              }
            if (preset_pin != null)
              {
                wr.addChildElement (PRESET_PIN_ELEM);
                preset_pin.writePINValue (wr);
              }
            wr.addChildElement (KEY_PAIR_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setStringAttribute (KEY_USAGE_ATTR, key_usage.getXMLName ());

            if (exportable)
              {
                wr.setBooleanAttribute (EXPORTABLE_ATTR, exportable);
              }

            key_alg_data.writeKeyAlgorithmData (wr);

            if (archival_key != null)
              {
                wr.addChildElement (PRIVATE_KEY_ARCHIVAL_KEY_ELEM);
                XMLSignatureWrapper.writeX509DataSubset (wr, new X509Certificate[]{archival_key});
                wr.getParent ();
              }

            wr.getParent ();

            if (device_pin_protected || preset_pin != null)
              {
                wr.getParent ();
              }
          }
      }

    Date server_time;

    String submit_url;

    int next_personal_code = 1;

    String key_prefix = "Key.";

    String key_man_prefix = "Section.";

    int next_key_id_suffix = 0;

    int next_key_man_suffix = 0;

    boolean need_signature_ns;

    boolean deferred_certification;

    String prefix;  // Default: no prefix

    TreeMap<String,KeyOperationRequestEncoder.KeyProperties> requested_keys = new TreeMap<String,KeyOperationRequestEncoder.KeyProperties> ();

    Vector<ManageObject> manage_objects = new Vector<ManageObject> ();

    Vector<PresetValue> preset_values = new Vector<PresetValue> ();

    ServerCookie server_cookie;


    // Constructors

    @SuppressWarnings("unused")
    private KeyOperationRequestEncoder () {}


    public KeyOperationRequestEncoder (String client_session_id,
                                       String server_session_id,
                                       String submit_url,
                                       Date server_time) throws IOException
      {
        super.client_session_id = client_session_id;
        super.server_session_id = server_session_id;
        this.submit_url = submit_url;
        this.server_time = server_time;
      }


    private static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    public PINPolicy createPINPolicy (PassphraseFormats format,
                                      int min_length,
                                      int max_length,
                                      int retry_limit) throws IOException
      {
        PINPolicy pin_policy = new PINPolicy ();
        pin_policy.format = format;
        pin_policy.min_length = min_length;
        pin_policy.max_length = max_length;
        pin_policy.retry_limit = retry_limit;
        if (format == null)
          {
            bad ("PassphraseFormats must not be null");
          }
        if (min_length > max_length)
          {
            bad ("min_length > max_length");
          }
        return pin_policy;
      }


    public PUKPolicy createPUKPolicy (String value,
                                      PassphraseFormats format,
                                      int retry_limit,
                                      boolean hidden) throws IOException
      {
        return new PUKPolicy (value, format, retry_limit, hidden);
      }


    private KeyProperties addKeyProperties (KeyGen2KeyUsage key_usage,
                                            KeyAlgorithmData key_alg_data,
                                            PINPolicy pin_policy,
                                            PUKPolicy puk_policy,
                                            PresetPIN preset_pin,
                                            boolean device_pin_protected) throws IOException
      {
        if (!device_pin_protected && puk_policy != null && pin_policy == null)
          {
            bad ("A PUKPolicy always requires a PINPolicy object as well");
          }
        KeyProperties rk = new KeyProperties (key_usage, key_alg_data, pin_policy, puk_policy, preset_pin, device_pin_protected);
        requested_keys.put (rk.getID (), rk);
        return rk;
      }


    public void setDeferredCertification (boolean flag)
      {
        deferred_certification = flag;
      }


    public KeyProperties createKeyWithPresetPIN (KeyGen2KeyUsage key_usage,
                                                 KeyAlgorithmData key_alg_data,
                                                 PINPolicy pin_policy,
                                                 PUKPolicy puk_policy,
                                                 String pin_value, boolean hidden, boolean user_modifiable) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        return addKeyProperties (key_usage, key_alg_data, pin_policy, puk_policy, new PresetPIN (pin_value, hidden, user_modifiable), false);
      }


    public KeyProperties createKey (KeyGen2KeyUsage key_usage,
                                    KeyAlgorithmData key_alg_data,
                                    PINPolicy pin_policy,
                                    PUKPolicy puk_policy) throws IOException
      {
        return addKeyProperties (key_usage, key_alg_data, pin_policy,  puk_policy, null, false);
      }


    public KeyProperties createDevicePINProtectedKey (KeyGen2KeyUsage key_usage,
                                                      KeyAlgorithmData key_alg_data) throws IOException
      {
        return addKeyProperties (key_usage, key_alg_data, null, null, null, true);
      }


    public ManageObject createManageObject ()
      {
        need_signature_ns = true;
        ManageObject kmc = new  ManageObject ();
        kmc.key_gen_req_enc = this;
        kmc.id = key_man_prefix + ++next_key_man_suffix;
        manage_objects.add (kmc);
        return kmc;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        if (need_signature_ns)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, client_session_id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        if (deferred_certification)
          {
            wr.setBooleanAttribute (DEFERRED_CERTIFICATION_ATTR, deferred_certification);
          }

        if (manage_objects.isEmpty () && requested_keys.isEmpty ())
          {
            bad ("Empty request not allowed!");
          }

        ////////////////////////////////////////////////////////////////////////
        // There MAY indeed be zero create objects...
        ////////////////////////////////////////////////////////////////////////
        if (!requested_keys.isEmpty ())
          {
            wr.addChildElement (CREATE_OBJECT_ELEM);
            KeyProperties last_req_key = null;
            for (KeyProperties req_key : requested_keys.values ())
              {
                if (last_req_key != null && last_req_key.puk_policy != null &&
                    last_req_key.puk_policy != req_key.puk_policy)
                  {
                    wr.getParent ();
                  }
                if (last_req_key != null && last_req_key.pin_policy != null &&
                    last_req_key.pin_policy != req_key.pin_policy)
                  {
                    wr.getParent ();
                  }
                if (req_key.puk_policy != null)
                  {
                    if (req_key.puk_policy.written)
                      {
                        if (last_req_key.puk_policy != req_key.puk_policy)
                          {
                            bad ("PUK grouping error");
                          }
                      }
                    else
                      {
                        wr.addChildElement (PUK_POLICY_ELEM);
                        req_key.puk_policy.writePolicy (wr);
                        req_key.puk_policy.written = true;
                      }
                  }
                if (req_key.pin_policy != null)
                  {
                    if (req_key.pin_policy.written)
                      {
                        if (last_req_key.pin_policy != req_key.pin_policy)
                          {
                            bad ("PIN grouping error");
                          }
                      }
                    else
                      {
                        wr.addChildElement (PIN_POLICY_ELEM);
                        req_key.pin_policy.writePolicy (wr);
                        req_key.pin_policy.written = true;
                      }
                  }
                req_key.writeRequest (wr);
                last_req_key = req_key;
              }
            if (last_req_key != null && last_req_key.pin_policy != null)
              {
                wr.getParent ();
              }
            if (last_req_key != null && last_req_key.puk_policy != null)
              {
                wr.getParent ();
              }
            wr.getParent ();
          }

        ////////////////////////////////////////////////////////////////////////
        // Key management operations are in this implementation output lastly
        ////////////////////////////////////////////////////////////////////////
        for (ManageObject kmc : manage_objects)
          {
            if (!kmc.signed)
              {
                bad ("ManageObject wasn't signed!");
              }
            wr.addWrapped (kmc.getOutputManageObect ());
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
