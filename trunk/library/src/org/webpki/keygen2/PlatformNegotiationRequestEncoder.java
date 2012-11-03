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

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationRequestEncoder extends PlatformNegotiationRequest
  {
    class ImageDescriptor
      {
        String mime_type;
        byte[] image_fingerprint;
        int width;
        int height;
        String logotype_url;
      }

    private String prefix;  // Default: no prefix
    
    Vector<ImageDescriptor> image_descriptors = new Vector<ImageDescriptor> ();

    Action action = Action.UPDATE;

    boolean needs_dsig_ns;

    // Constructors

    public PlatformNegotiationRequestEncoder (String server_session_id,
                                              String submit_url)
      {
        this.server_session_id = server_session_id;
        this.submit_url = submit_url;
      }
    
    
    public void setAction (Action action)
      {
        this.action = action;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }
    

    boolean privacy_enabled_set;
    
    public void setPrivacyEnabled (boolean flag)
      {
        privacy_enabled_set = true;
        privacy_enabled = flag;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        needs_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    public PlatformNegotiationRequestEncoder addLogotype (String logotype_url,
                                                          String mime_type,
                                                          byte[] image_fingerprint,
                                                          int width,
                                                          int height)
      {
        ImageDescriptor im_des = new ImageDescriptor ();
        im_des.logotype_url = logotype_url;
        im_des.mime_type = mime_type;
        im_des.image_fingerprint = image_fingerprint;
        im_des.width = width;
        im_des.height = height;
        image_descriptors.add (im_des);
        return this;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ACTION_ATTR, action.getXMLName ());

        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        BasicCapabilities.write (wr, basic_capabilities);

        if (privacy_enabled_set)
          {
            wr.setBooleanAttribute (PRIVACY_ENABLED_ATTR, privacy_enabled);
          }
        
        if (needs_dsig_ns) XMLSignatureWrapper.addXMLSignatureNS (wr);

        ////////////////////////////////////////////////////////////////////////
        // Issuer logotype(s)
        ////////////////////////////////////////////////////////////////////////
        if (image_descriptors.isEmpty ())
          {
            throw new IOException ("There must be at least one logotype image defined");
          }
        for (ImageDescriptor im_des : image_descriptors)
          {
            wr.addChildElement (ISSUER_LOGOTYPE_ELEM);
            wr.setStringAttribute (MIME_TYPE_ATTR, im_des.mime_type);
            wr.setStringAttribute (LOGOTYPE_URL_ATTR, im_des.logotype_url);
            wr.setIntAttribute (WIDTH_ATTR, im_des.width);
            wr.setIntAttribute (HEIGHT_ATTR, im_des.height);
            wr.setBinaryAttribute (IMAGE_FINGERPRINT_ATTR, im_des.image_fingerprint);
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
