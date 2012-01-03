package org.webpki.webutil.proxy;

import java.io.Serializable;

/**
 * HTTP proxy object containing an upload operation. 
 * Only for proxy-internal use.
 */
class UploadObject extends ClientObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    private UploadPayloadObject payload;

    UploadPayloadObject getPayload ()
      {
        return payload;
      }

    UploadObject (String client_id, UploadPayloadObject payload)
      {
        super (client_id);
        this.payload = payload;
      }
  }
