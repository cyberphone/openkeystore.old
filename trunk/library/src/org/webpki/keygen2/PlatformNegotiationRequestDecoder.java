/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationRequestDecoder extends PlatformNegotiationRequest
  {
    public class ImageDescriptor
      {
        private ImageDescriptor () {}
        
        int width;
        int height;
        String mime_type;
        String logotype_url;
        byte[] image_fingerprint;
        
        public int getWidth ()
          {
            return width;
          }
        
        public int getHeight ()
          {
            return height;
          }
        
        public String getMimeType ()
          {
            return mime_type;
          }
        
        public String getLogotypeURL ()
          {
            return logotype_url;
          }
        
        public byte[] getImageFingerprint ()
          {
            return image_fingerprint;
          }
      }
    
    Vector<ImageDescriptor> image_descriptors = new Vector<ImageDescriptor> ();

    private XMLSignatureWrapper signature;  // Optional


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


    public ImageDescriptor[] getIssuerLogotypes ()
      {
        return image_descriptors.toArray (new ImageDescriptor[0]);
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public boolean getPrivacyEnabledFlag ()
      {
        return privacy_enabled;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);
        
        privacy_enabled = ah.getBooleanConditional (PRIVACY_ENABLED_ATTR);

        readBasicCapabilities (ah);

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        rd.getChild ();

        do
          {
            rd.getNext (ISSUER_LOGOTYPE_ELEM);
            ImageDescriptor im_des = new ImageDescriptor ();
            im_des.mime_type = ah.getString (MIME_TYPE_ATTR);
            im_des.logotype_url = ah.getString (LOGOTYPE_URL_ATTR);
            im_des.width = ah.getInt (WIDTH_ATTR);
            im_des.height = ah.getInt (HEIGHT_ATTR);
            im_des.image_fingerprint = ah.getBinary (IMAGE_FINGERPRINT_ATTR);
            image_descriptors.add (im_des);
          }
        while (rd.hasNext (ISSUER_LOGOTYPE_ELEM));

        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }
  }
