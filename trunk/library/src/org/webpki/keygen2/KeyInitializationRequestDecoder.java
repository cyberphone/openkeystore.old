package org.webpki.keygen2;

import java.io.IOException;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Set;
import java.util.EnumSet;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.ECDomains;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationRequestDecoder extends KeyInitializationRequest
  {
    abstract class PresetValueReference
      {
        byte[] value;

        PresetValueReference (DOMReaderHelper rd) throws IOException
          {
            value = rd.getAttributeHelper ().getBinary (VALUE_ATTR);
          }
        
        public byte[] getValue ()
          {
            return value;
          }

      }


    public class PresetPIN extends PresetValueReference
      {
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


    public class PUKPolicy extends PresetValueReference
      {
        Object user_data;

        PassphraseFormats format;

        int retry_limit;
        
        String id;
 
        PUKPolicy (DOMReaderHelper rd) throws IOException
          {
            super (rd);
            retry_limit = rd.getAttributeHelper ().getInt (RETRY_LIMIT_ATTR);
            id = rd.getAttributeHelper ().getString (ID_ATTR);
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

        
        public String getID ()
          {
            return id;
          }
      }


    public class PINPolicy
      {
        String id;
        
        PUKPolicy puk_policy;
        
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
            
            id = ah.getString (ID_ATTR);

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


        public Set<PatternRestrictions> getPatternRestrictions ()
          {
            return pattern_restrictions;
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


        public String getID ()
          {
            return id;
          }


        public void setUserData (Object user_data)
          {
            this.user_data = user_data;
          }


        public Object getUserData ()
          {
            return user_data;
          }

        
        public PUKPolicy getPUKPolicy ()
          {
            return puk_policy;
          }

      }


    public abstract class KeyAlgorithmData
      {
      }


    public class RSA extends KeyAlgorithmData
      {
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


    public class EC extends KeyAlgorithmData
      {
        ECDomains named_curve;

        EC (ECDomains named_curve)
          {
            this.named_curve = named_curve;
          }


        public ECDomains getNamedCurve ()
          {
            return named_curve;
          }

      }


    public class KeyObject
      {
        String id;
        
        boolean start_of_puk_group;

        boolean start_of_pin_group;

        PINPolicy pin_policy;

        PresetPIN preset_pin;

        boolean device_pin_protected;

        KeyGen2KeyUsage key_usage;

        KeyAlgorithmData key_algorithm_data;

        boolean exportable;

        KeyObject (DOMReaderHelper rd, 
                   PINPolicy pin_policy,
                   boolean start_of_pin_group, 
                   PresetPIN preset_pin,
                   boolean device_pin_protected) throws IOException
          {
            rd.getNext (KEY_PAIR_ELEM);
            this.pin_policy = pin_policy;
            this.start_of_pin_group = start_of_pin_group;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;

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
                rd.getNext (EC_ELEM);
                String ec_uri = ah.getString (NAMED_CURVE_ATTR);
                if (ec_uri.startsWith ("urn:oid:"))
                  {
                    key_algorithm_data = new EC (ECDomains.getECDomainFromOID (ec_uri.substring (8)));
                  }
                else
                  {
                    bad ("urn:oid: expected");
                  }
              }
            rd.getParent ();
          }


        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
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

      }


    private void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    private KeyObject readKeyProperties (DOMReaderHelper rd,
                                         PINPolicy pin_policy,
                                         boolean start_of_pin_group) throws IOException
      {
        KeyObject rk;
        if (rd.hasNext (PRESET_PIN_ELEM))
          {
            rd.getNext (PRESET_PIN_ELEM);
            PresetPIN preset = new PresetPIN (rd);
            rd.getChild ();
            request_objects.add (rk = new KeyObject (rd, pin_policy, start_of_pin_group, preset, false));
            rd.getParent ();
          }
        else
          {
            request_objects.add (rk = new KeyObject (rd, pin_policy, start_of_pin_group, null, false));
          }
        return rk;
      }
      

    private void readKeyProperties (DOMReaderHelper rd, boolean device_pin_protected) throws IOException
      {
        request_objects.add (new KeyObject (rd, null, false, null, device_pin_protected));
      }


    private void readPINPolicy (DOMReaderHelper rd, boolean puk_start, PUKPolicy puk_policy) throws IOException
      {
        boolean start = true;
        rd.getNext (PIN_POLICY_ELEM);
        PINPolicy upp = new PINPolicy (rd);
        upp.puk_policy = puk_policy;
        rd.getChild ();
        do
          {
            KeyObject rk = readKeyProperties (rd, upp, start);
            rk.start_of_puk_group = puk_start;
            puk_start = false;
            start = false;
          }
        while (rd.hasNext ());
        rd.getParent ();
      }


    private Vector<KeyObject> request_objects = new Vector<KeyObject> ();
      
    private String submit_url;

    private ServerCookie server_cookie;     // Optional

    private boolean deferred_certification;

    private XMLSignatureWrapper signature;  // Optional

    private String server_session_id;

    private String client_session_id;

    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getServerSessionID ()
      {
        return server_session_id;
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


    public KeyObject[] getKeyObjects () throws IOException
      {
        return request_objects.toArray (new KeyObject[0]);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        deferred_certification = ah.getBooleanConditional (DEFERRED_CERTIFICATION_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the request and management elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
         while (true)
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
            else if (rd.hasNext (DEVICE_SYNCHRONIZED_PIN_ELEM))
              {
                rd.getNext (DEVICE_SYNCHRONIZED_PIN_ELEM);
                rd.getChild ();
                readKeyProperties (rd, true);
                rd.getParent ();
              }
            else break;
          }
 
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

