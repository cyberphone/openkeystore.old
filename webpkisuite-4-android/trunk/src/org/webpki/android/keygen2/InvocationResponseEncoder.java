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
package org.webpki.android.keygen2;
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
import java.io.IOException;

import java.util.LinkedHashMap;

import org.webpki.android.json.JSONArrayWriter;
import org.webpki.android.json.JSONEncoder;
import org.webpki.android.json.JSONObjectWriter;

import static org.webpki.android.keygen2.KeyGen2Constants.*;

public class InvocationResponseEncoder extends JSONEncoder
  {
    private static final long serialVersionUID = 1L;

    String server_session_id;
    
    byte[] nonce;  // For VMs
    
    LinkedHashMap<String,InvocationRequestDecoder.CAPABILITY> queried_capabilities;   
    
    LinkedHashMap<String,String[]> returned_values = new LinkedHashMap<String,String[]> ();
    
    class ImageAttributes
      {
        String mime_type;
        int width;
        int height;
      }

    LinkedHashMap<String,ImageAttributes> image_preferences = new LinkedHashMap<String,ImageAttributes> ();

    void addCapability (String type_uri, InvocationRequestDecoder.CAPABILITY capability) throws IOException
      {
        InvocationRequestDecoder.CAPABILITY current = queried_capabilities.get (type_uri);
        if (current == null || current != InvocationRequestDecoder.CAPABILITY.UNDEFINED)
          {
            KeyGen2Validator.bad ("State error for URI: " + type_uri);
          }
        queried_capabilities.put (type_uri, capability);
      }

    public InvocationResponseEncoder addImagePreference (String type_uri,
                                                         String mime_type,
                                                         int width,
                                                         int height) throws IOException
      {
        addCapability (type_uri, InvocationRequestDecoder.CAPABILITY.IMAGE_ATTRIBUTES);
        ImageAttributes im_pref = new ImageAttributes ();
        im_pref.mime_type = mime_type;
        im_pref.width = width;
        im_pref.height = height;
        image_preferences.put (type_uri, im_pref);
        return this;
      }

    public InvocationResponseEncoder addSupportedFeature (String type_uri) throws IOException
      {
        addCapability (type_uri, InvocationRequestDecoder.CAPABILITY.URI_FEATURE);
        return this;
      }

    public InvocationResponseEncoder addClientValues (String type_uri, String[] values) throws IOException
      {
        addCapability (type_uri, InvocationRequestDecoder.CAPABILITY.VALUES);
        if (values.length == 0)
          {
            KeyGen2Validator.bad ("Zero length array not allowed, URI: " + type_uri);
          }
        returned_values.put (type_uri, values);
        return this;
      }

    public InvocationResponseEncoder (InvocationRequestDecoder decoder)
      {
        this.server_session_id = decoder.server_session_id;
        this.queried_capabilities = decoder.queried_capabilities;
      }
    
    public void setNonce (byte[] nonce)
      {
        this.nonce = nonce;
      }

    @Override
    @SuppressWarnings("fallthrough")
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);
        
        ////////////////////////////////////////////////////////////////////////
        // VM mandatory option
        ////////////////////////////////////////////////////////////////////////
        if (nonce != null)
          {
            wr.setBinary (NONCE_JSON, nonce);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional client capabilities
        ////////////////////////////////////////////////////////////////////////
        if (!queried_capabilities.isEmpty ())
          {
            JSONArrayWriter aw = wr.setArray (CLIENT_CAPABILITIES_JSON);
            for (String uri : queried_capabilities.keySet ())
              {
                JSONObjectWriter ow = aw.setObject ().setString (TYPE_JSON, uri);
                boolean supported = false;
                switch (queried_capabilities.get (uri))
                  {
                    case IMAGE_ATTRIBUTES:
                      ImageAttributes im_pref = image_preferences.get (uri);
                      ow.setObject (IMAGE_ATTRIBUTES_JSON)
                           .setString (MIME_TYPE_JSON, im_pref.mime_type)
                           .setInt (WIDTH_JSON, im_pref.width)
                           .setInt (HEIGHT_JSON, im_pref.height);
                      break;

                    case VALUES:
                      ow.setStringArray (VALUES_JSON, returned_values.get (uri));
                      break;

                    case URI_FEATURE:
                      supported = true;
                    default:
                      ow.setBoolean (SUPPORTED_JSON, supported);
                  }
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return INVOCATION_RESPONSE_JSON;
      }

    @Override
    public String getContext ()
      {
        return KEYGEN2_NS;
      }
  }
