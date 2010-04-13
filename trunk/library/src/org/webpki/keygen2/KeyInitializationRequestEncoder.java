package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Date;
import java.util.TreeMap;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.ECDomains;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationRequestEncoder extends KeyInitializationRequest implements Serializable
  {
    private static final long serialVersionUID = 1L;

    class PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] value;

        PresetValue (byte[] value) throws IOException
          {
            this.value = value;
          }

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.setBinaryAttribute (VALUE_ATTR, value);
          }
      }


    private class PresetPIN extends PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean user_modifiable;

        PresetPIN (byte[] value, boolean user_modifiable) throws IOException
          {
            super (value);
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

        PUKPolicy (byte[] value, PassphraseFormats format, int retry_limit) throws IOException
          {
            super (value);
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

        byte[] preset_test;

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

        public static final class EC extends KeyAlgorithmData implements Serializable
          {

            private static final long serialVersionUID = 1L;

            ECDomains named_curve;

            @SuppressWarnings("unused")
            private EC () {}

            public EC (ECDomains named_curve)
              {
                this.named_curve = named_curve;
              }


            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                wr.addChildElement (EC_ELEM);
                wr.setStringAttribute (NAMED_CURVE_ATTR, named_curve.getURI ());
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
                         (pin_policy.preset_test != null && preset_pin == null)))
                      {
                        bad ("\"shared\" PIN keys must either have no \"preset_pin\" " +
                             "value or all be preset");
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

    TreeMap<String,KeyInitializationRequestEncoder.KeyProperties> requested_keys = new TreeMap<String,KeyInitializationRequestEncoder.KeyProperties> ();

    Vector<PresetValue> preset_values = new Vector<PresetValue> ();

    ServerCookie server_cookie;


    // Constructors

    @SuppressWarnings("unused")
    private KeyInitializationRequestEncoder () {}


    public KeyInitializationRequestEncoder (String client_session_id,
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


    public PUKPolicy createPUKPolicy (byte[] value,
                                      PassphraseFormats format,
                                      int retry_limit,
                                      boolean hidden) throws IOException
      {
        return new PUKPolicy (value, format, retry_limit);
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
                                                 byte[] pin_value, boolean hidden, boolean user_modifiable) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        return addKeyProperties (key_usage, key_alg_data, pin_policy, puk_policy, new PresetPIN (pin_value, user_modifiable), false);
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

        ////////////////////////////////////////////////////////////////////////
        // There MUST not be zero keys to initialize...
        ////////////////////////////////////////////////////////////////////////
        if (requested_keys.isEmpty ())
          {
            bad ("Empty request not allowd!");
          }
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


        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
