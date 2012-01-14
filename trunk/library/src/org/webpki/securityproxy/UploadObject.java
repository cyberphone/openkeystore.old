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
package org.webpki.securityproxy;

import java.io.Serializable;

/**
 * Security proxy object containing an upload operation. 
 * Only for proxy-internal use.
 */
class UploadObject extends ClientObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    private ProxyUploadWrapper payload;

    ProxyUploadWrapper getPayload (UploadEventHandler handler)
      {
        payload.handler = handler;
        return payload;
      }

    UploadObject (String client_id, ProxyUploadWrapper payload)
      {
        super (client_id);
        this.payload = payload;
      }
  }
