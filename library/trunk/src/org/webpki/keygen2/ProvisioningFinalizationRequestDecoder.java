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
package org.webpki.keygen2;

import java.io.IOException;
import java.util.Vector;
import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.ArrayUtil;
import org.webpki.crypto.CertificateFilter;
import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;

    public class PostOperation
      {
        public static final int DELETE_KEY            = 0;
        public static final int UNLOCK_KEY            = 1;
        public static final int UPDATE_KEY            = 2;
        public static final int CLONE_KEY_PROTECTION  = 3;
        
        String client_session_id;
        
        String server_session_id;
        
        byte[] mac;
        
        byte[] certificate_fingerprint;
        
        byte[] authorization;
        
        int post_operation;
        
        PostOperation (String client_session_id,
                       String server_session_id,
                       byte[] certificate_fingerprint,
                       byte[] authorization,
                       byte[] mac,
                       int post_operation)
          {
            this.client_session_id = client_session_id;
            this.server_session_id = server_session_id;
            this.certificate_fingerprint = certificate_fingerprint;
            this.authorization = authorization;
            this.mac = mac;
            this.post_operation = post_operation;
          }
        
        public byte[] getMac ()
          {
            return mac;
          }
        
        public byte[] getCertificateFingerprint ()
          {
            return certificate_fingerprint;
          }
        
        public byte[] getAuthorization ()
          {
            return authorization;
          }
        
        public int getPostOperation ()
          {
            return post_operation;
          }
        
        public String getClientSessionId ()
          {
            return client_session_id;
          }
        
        public String getServerSessionId ()
          {
            return server_session_id;
          }
  
      }

    public abstract class Extension
      {
  
        String type;
        
        public String getExtensionType ()
          {
            return type;
          }
        
        byte[] mac;
        
        public byte[] getMac ()
          {
            return mac;
          }
        
        public abstract byte getSubType ();
        
        public String getQualifier () throws IOException
          {
            return "";
          }
        
        public abstract byte[] getExtensionData () throws IOException;
        
        Extension (JSONObjectReader rd, IssuedCredential cpk) throws IOException
          {
            type = rd.getString (TYPE_JSON);
            mac = KeyGen2Validator.getMac (rd);
            cpk.extensions.add (this);
          }
      }


    class StandardExtension extends Extension
      {
        byte[] data;

        StandardExtension (JSONObjectReader rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            data = rd.getBinary (EXTENSION_DATA_JSON);
          }

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
          }


        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
      }

    
    class EncryptedExtension extends Extension
      {
        byte[] data;
         
        EncryptedExtension (JSONObjectReader rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            this.data = rd.getBinary (EXTENSION_DATA_JSON);
          }


        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
          }
  
  
        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
      }


    class Property
      {
        private Property () {}

        String name;

        String value;

        boolean writable;
      }
    

    class PropertyBag extends Extension
      {
        Vector<Property> properties = new Vector<Property> ();

        PropertyBag (JSONObjectReader rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            JSONArrayReader props = rd.getArray (PROPERTIES_JSON);
            do
              {
                JSONObjectReader prop_rd = props.getObject ();
                Property property = new Property ();
                property.name = prop_rd.getString (NAME_JSON);
                property.value = prop_rd.getString (VALUE_JSON);
                property.writable = prop_rd.getBooleanConditional (WRITABLE_JSON);
                properties.add (property);
              }
            while (props.hasMore ());
          }

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
          }


        private byte[] getStringData (String string) throws IOException
          {
            byte[] data = string.getBytes ("UTF-8");
            return ArrayUtil.add (new byte[]{(byte)(data.length >>> 8), (byte)data.length}, data);
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            byte[] total = new byte[0];
            for (Property prop : properties)
              {
                total = ArrayUtil.add (total,
                                       ArrayUtil.add (getStringData (prop.name),
                                                      ArrayUtil.add (new byte[]{prop.writable ? (byte)1 : (byte)0},
                                                                     getStringData (prop.value))));
              }
            return total;
          }
      }


    class Logotype extends Extension
      {
        byte[] data;
        
        String mime_type;
  
        Logotype (JSONObjectReader rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            mime_type = rd.getString (MIME_TYPE_JSON);
            data = rd.getBinary (EXTENSION_DATA_JSON);
          }

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
          }
  
        @Override
        public String getQualifier ()
          {
            return mime_type;
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
      }


    public class IssuedCredential
      {
        X509Certificate[] certificate_path;

        String id;

        byte[] encrypted_symmetric_key;

        byte[] symmetric_key_mac;

        byte[] encrypted_private_key;

        byte[] private_key_mac;

        byte[] mac;
        
        boolean trust_anchor;

        Vector<Extension> extensions = new Vector<Extension> ();
        
        PostOperation post_operation;

        IssuedCredential () { }


        IssuedCredential (JSONObjectReader rd) throws IOException
          {
            id = rd.getString (ID_JSON);
            certificate_path = rd.getCertificatePath ();            
            mac = KeyGen2Validator.getMac (rd);

            trust_anchor = rd.getBooleanConditional (TRUST_ANCHOR_JSON);
            if (trust_anchor)
              {
                if (certificate_path[certificate_path.length - 1].getBasicConstraints () < 0)
                  {
                    throw new IOException ("The \"" + TRUST_ANCHOR_JSON + "\" option requires a CA certificate");
                  }
              }

            if (rd.hasProperty (IMPORT_SYMMETRIC_KEY_JSON))
              {
                JSONObjectReader import_key = rd.getObject(IMPORT_SYMMETRIC_KEY_JSON);
                encrypted_symmetric_key = import_key.getBinary (ENCRYPTED_KEY_JSON);
                symmetric_key_mac = KeyGen2Validator.getMac (import_key);
              }
            else if (rd.hasProperty (IMPORT_PRIVATE_KEY_JSON))
              {
                JSONObjectReader import_key = rd.getObject(IMPORT_PRIVATE_KEY_JSON);
                encrypted_private_key = import_key.getBinary (ENCRYPTED_KEY_JSON);
                private_key_mac = KeyGen2Validator.getMac (import_key);
              }

            for (JSONObjectReader extension : getObjectArrayConditional (rd, EXTENSIONS_JSON))
              {
                new StandardExtension (extension, this);
              }

            for (JSONObjectReader encrypted_extension : getObjectArrayConditional (rd, ENCRYPTED_EXTENSIONS_JSON))
              {
                new EncryptedExtension (encrypted_extension, this);
              }

            for (JSONObjectReader property_bag : getObjectArrayConditional (rd, PROPERTY_BAGS_JSON))
              {
                new PropertyBag (property_bag, this);
              }

            for (JSONObjectReader logotype : getObjectArrayConditional (rd, LOGOTYPES_JSON))
              {
                new Logotype (logotype, this);
              }

            if (rd.hasProperty (CLONE_KEY_PROTECTION_JSON))
              {
                post_operation = readPostOperation (rd.getObject (CLONE_KEY_PROTECTION_JSON), PostOperation.CLONE_KEY_PROTECTION);
              }
            else if (rd.hasProperty (UPDATE_KEY_JSON))
              {
                post_operation = readPostOperation (rd.getObject (UPDATE_KEY_JSON), PostOperation.UPDATE_KEY);
              }
          }


        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
          }


        public byte[] getOptionalSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        public byte[] getSymmetricKeyMac ()
          {
            return symmetric_key_mac;
          }


        public byte[] getOptionalPrivateKey ()
          {
            return encrypted_private_key;
          }


        public byte[] getPrivateKeyMac ()
          {
            return private_key_mac;
          }


        public String getId ()
          {
            return id;
          }

        public byte[] getMac ()
          {
            return mac;
          }


        public Extension[] getExtensions ()
          {
            return extensions.toArray (new Extension[0]);
          }
        
        public PostOperation getPostOperation ()
          {
            return post_operation;
          }

        public boolean getTrustAnchorFlag ()
          {
            return trust_anchor;
          }

      }
    
    private PostOperation readPostOperation (JSONObjectReader rd, int post_op) throws IOException
      {
        return new PostOperation (KeyGen2Validator.getID (rd, CLIENT_SESSION_ID_JSON),
                                  KeyGen2Validator.getID (rd, SERVER_SESSION_ID_JSON),
                                  rd.getBinary (CertificateFilter.CF_FINGER_PRINT),
                                  rd.getBinary (AUTHORIZATION_JSON),
                                  KeyGen2Validator.getMac (rd),
                                  post_op);
      }

    private Vector<IssuedCredential> issued_keys = new Vector<IssuedCredential> ();
    
    private Vector<PostOperation> post_unlock_keys = new Vector<PostOperation> ();
      
    private Vector<PostOperation> post_delete_keys = new Vector<PostOperation> ();
    
    private String client_session_id;

    private String server_session_id;

    private String submit_url;

    private byte[] close_session_mac;
    
    private byte[] close_session_nonce;


    public String getServerSessionId ()
      {
        return server_session_id;
      }


    public String getClientSessionId ()
      {
        return client_session_id;
      }


    public String getSubmitUrl ()
      {
        return submit_url;
      }


    public IssuedCredential[] getIssuedCredentials ()
      {
        return issued_keys.toArray (new IssuedCredential[0]);
      }
    
    
    public PostOperation[] getPostUnlockKeys ()
      {
        return post_unlock_keys.toArray (new PostOperation[0]);
      }

    
    public PostOperation[] getPostDeleteKeys ()
      {
        return post_delete_keys.toArray (new PostOperation[0]);
      }


    public byte[] getCloseSessionMac ()
      {
        return close_session_mac;
      }

    
    public byte[] getCloseSessionNonce ()
      {
        return close_session_nonce;
      }


    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, CLIENT_SESSION_ID_JSON);

        submit_url = getURL (rd, SUBMIT_URL_JSON);
        
        close_session_nonce = rd.getBinary (NONCE_JSON);

        close_session_mac = KeyGen2Validator.getMac (rd);
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the issued_keys [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional (rd, ISSUED_CREDENTIALS_JSON))
          {
            issued_keys.add (new IssuedCredential (keys));
          }
 
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning unlocks
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional (rd, UNLOCK_KEYS_JSON))
          {
            post_unlock_keys.add (readPostOperation (keys, PostOperation.UNLOCK_KEY));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning deletes
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional (rd, DELETE_KEYS_JSON))
          {
            post_delete_keys.add (readPostOperation (keys, PostOperation.DELETE_KEY));
          }
      }

    @Override
    public String getQualifier ()
      {
        return KeyGen2Messages.PROVISIONING_FINALIZATION_REQUEST.getName ();
      }
  }
