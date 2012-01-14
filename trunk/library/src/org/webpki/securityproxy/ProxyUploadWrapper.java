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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Security proxy payload data object containing an upload operation.
 */
public class ProxyUploadWrapper implements Serializable
  {
    private static final long serialVersionUID = 1L;

    byte[] data;
    
    UploadEventHandler handler;

    ProxyUploadWrapper ()
      {
      }

    public ProxyUploadWrapper (byte[] data)
      {
        this.data = data;
      }

    public ProxyUploadWrapper (Object object) throws IOException
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        new ObjectOutputStream (baos).writeObject (object);
        this.data = baos.toByteArray ();
      }
    
    public byte[] getData ()
      {
        return data;
      }

    public Object getObject () throws IOException, ClassNotFoundException
      {
        return new ProxyObjectInputStream (new ByteArrayInputStream (data), handler).readObject ();
      }
  }
