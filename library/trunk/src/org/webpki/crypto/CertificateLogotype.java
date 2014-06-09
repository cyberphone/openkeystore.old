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
package org.webpki.crypto;

import org.webpki.util.MIMETypedObject;


public class CertificateLogotype implements MIMETypedObject
  {
    private byte[] data;

    private String mime_type;


    public String getMIMEType ()
      {
        return mime_type;
      }


    public byte[] getData ()
      {
        return data;
      }


    public CertificateLogotype (byte[] data, String mime_type)
      {
        this.data = data;
        this.mime_type = mime_type;
      }

  }
