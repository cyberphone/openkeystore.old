/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDeploymentRequestDecoder extends CredentialDeploymentRequest
  {
    public static class PostOperation
      {
        public static final int DELETE_KEY            = 0;
        public static final int UPDATE_KEY            = 1;
        public static final int CLONE_KEY_PROTECTION  = 2;
        
        String client_session_id;
        
        String server_session_id;
        
        byte[] mac;
        
        byte[] certificate_fingerprint;
        
        byte[] km_authentication;
        
        int post_operation;
        
        PostOperation (String client_session_id,
                       String server_session_id,
                       byte[] certificate_fingerprint,
                       byte[] km_authentication,
                       byte[] mac,
                       int post_operation)
          {
            this.client_session_id = client_session_id;
            this.server_session_id = server_session_id;
            this.certificate_fingerprint = certificate_fingerprint;
            this.km_authentication = km_authentication;
            this.mac = mac;
            this.post_operation = post_operation;
          }
        
        public byte[] getMAC ()
          {
            return mac;
          }
        
        public byte[] getCertificateFingerprint ()
          {
            return certificate_fingerprint;
          }
        
        public byte[] getKMAuthentication ()
          {
            return km_authentication;
          }
        
        public int getPostOperation ()
          {
            return post_operation;
          }
        
        public String getClientSessionID ()
          {
            return client_session_id;
          }
        
        public String getServerSessionID ()
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
        
        public byte[] getMAC ()
          {
            return mac;
          }
        
        public abstract byte getSubType ();
        
        public byte[] getQualifier () throws IOException
          {
            return new byte[0];
          }
        
        public abstract byte[] getExtensionData () throws IOException;
        
        Extension (DOMReaderHelper rd, DeployedKeyEntry cpk) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            type = ah.getString (TYPE_ATTR);
            mac = ah.getBinary (MAC_ATTR);
            cpk.extensions.add (this);
          }
      }


    class StandardExtension extends Extension
      {
        byte[] data;

        StandardExtension (byte[] data, DOMReaderHelper rd, DeployedKeyEntry cpk) throws IOException
          {
            super (rd, cpk);
            this.data = data;
          }


        @Override
        public byte getSubType ()
          {
            return (byte)0x00;
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
         
        EncryptedExtension (byte[] data, DOMReaderHelper rd, DeployedKeyEntry cpk) throws IOException
          {
            super (rd, cpk);
            this.data = data;
          }
  
  
        @Override
        public byte getSubType ()
          {
            return (byte)0x01;
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
        private PropertyBag (DOMReaderHelper rd, DeployedKeyEntry cpk) throws IOException
          {
            super (rd, cpk);
          }

        Vector<Property> properties = new Vector<Property> ();

        @Override
        public byte getSubType ()
          {
            return (byte)0x02;
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
  
        Logotype (byte[] data, String mime_type, DOMReaderHelper rd, DeployedKeyEntry cpk) throws IOException
          {
            super (rd, cpk);
            this.mime_type = mime_type;
            this.data = data;
          }
  
        @Override
        public byte getSubType ()
          {
            return (byte)0x03;
          }
  
        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
      }


    public class DeployedKeyEntry
      {
        X509Certificate[] certificate_path;

        String id;

        byte[] encrypted_symmetric_key;

        byte[] symmetric_key_mac;

        byte[] encrypted_private_key;

        byte[] private_key_mac;

        byte[] mac;

        Vector<Extension> extensions = new Vector<Extension> ();
        
        PostOperation post_operation;

        DeployedKeyEntry () { }


        DeployedKeyEntry (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            rd.getNext (CERTIFICATE_PATH_ELEM);
            id = ah.getString (ID_ATTR);
            mac = ah.getBinary (MAC_ATTR);
            rd.getChild ();

            certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);

            if (rd.hasNext (SYMMETRIC_KEY_ELEM))
              {
                encrypted_symmetric_key = rd.getBinary (SYMMETRIC_KEY_ELEM);
                symmetric_key_mac = ah.getBinary (MAC_ATTR);
              }
            else if (rd.hasNext (PRIVATE_KEY_ELEM))
              {
                encrypted_private_key = rd.getBinary (PRIVATE_KEY_ELEM);
                private_key_mac = ah.getBinary (MAC_ATTR);
              }

            while (rd.hasNext ())
              {
                if (rd.hasNext (PROPERTY_BAG_ELEM))
                  {
                    rd.getNext (PROPERTY_BAG_ELEM);
                    PropertyBag property_bag = new PropertyBag (rd, this);
                    rd.getChild ();
                    while (rd.hasNext (PROPERTY_ELEM))
                      {
                        rd.getNext (PROPERTY_ELEM);
                        Property property = new Property ();
                        property.name = ah.getString (NAME_ATTR);
                        property.value = ah.getString (VALUE_ATTR);
                        property.writable = ah.getBooleanConditional (WRITABLE_ATTR);
                        property_bag.properties.add (property);
                      }
                    rd.getParent ();
                  }
                else if (rd.hasNext (LOGOTYPE_ELEM))
                  {
                    new Logotype (rd.getBinary (LOGOTYPE_ELEM), ah.getString (MIME_TYPE_ATTR), rd, this);
                  }
                else if (rd.hasNext (EXTENSION_ELEM))
                  {
                    new StandardExtension (rd.getBinary (EXTENSION_ELEM), rd, this);
                  }
                else if (rd.hasNext (ENCRYPTED_EXTENSION_ELEM))
                  {
                    new EncryptedExtension (rd.getBinary (ENCRYPTED_EXTENSION_ELEM), rd, this);
                  }
                else if (rd.hasNext (CLONE_KEY_PROTECTION_ELEM))
                  {
                    post_operation = readPostOperation (rd, PostOperation.CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_ELEM);
                  }
                else
                  {
                    post_operation = readPostOperation (rd, PostOperation.UPDATE_KEY, UPDATE_KEY_ELEM);
                  }
              }
            rd.getParent ();
          }


        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        public byte[] getSymmetricKeyMac ()
          {
            return symmetric_key_mac;
          }


        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }


        public byte[] getPrivateKeyMac ()
          {
            return private_key_mac;
          }


        public String getID ()
          {
            return id;
          }

        public byte[] getMAC ()
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

      }
    
    private PostOperation readPostOperation (DOMReaderHelper rd, int post_op, String xml_elem) throws IOException
      {
        rd.getNext (xml_elem);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        return new PostOperation (ah.getString (CLIENT_SESSION_ID_ATTR),
                                  ah.getString (SERVER_SESSION_ID_ATTR),
                                  ah.getBinary (CERTIFICATE_FINGERPRINT_ATTR),
                                  ah.getBinary (KM_AUTHENTICATION_ATTR),
                                  ah.getBinary (MAC_ATTR),
                                  post_op);
      }

    private Vector<DeployedKeyEntry> deployed_key_entries = new Vector<DeployedKeyEntry> ();
    
    private Vector<PostOperation> pp_delete_keys = new Vector<PostOperation> ();
      
    private String client_session_id;

    private String server_session_id;

    private String server_time;

    private String submit_url;

    private ServerCookie server_cookie;                     // Optional

    private XMLSignatureWrapper signature;                  // Optional

    private byte[] close_session_mac;
    
    private byte[] close_session_nonce;


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
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


    public DeployedKeyEntry[] getDeployedKeyEntrys ()
      {
        return deployed_key_entries.toArray (new DeployedKeyEntry[0]);
      }
    
    
    public PostOperation[] getPostProvisioningDeleteKeys ()
      {
        return pp_delete_keys.toArray (new PostOperation[0]);
      }


    public byte[] getCloseSessionMAC ()
      {
        return close_session_mac;
      }

    
    public byte[] getCloseSessionNonce ()
      {
        return close_session_nonce;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        server_session_id = ah.getString (ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);
        
        close_session_mac = ah.getBinary (MAC_ATTR);
        
        close_session_nonce = ah.getBinary (NONCE_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the deployed_key_entries [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do 
          {
            deployed_key_entries.add (new DeployedKeyEntry (rd));
          }
        while (rd.hasNext (CERTIFICATE_PATH_ELEM));

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning deletes
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (DELETE_KEY_ELEM))
          {
            pp_delete_keys.add (readPostOperation (rd, PostOperation.DELETE_KEY, DELETE_KEY_ELEM));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }
