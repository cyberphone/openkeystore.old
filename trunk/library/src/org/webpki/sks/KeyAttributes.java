/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.sks;

import java.security.cert.X509Certificate;


public class KeyAttributes
  {
    boolean is_symmetric_key;
    
    byte app_usage;
    
    String friendly_name;

    X509Certificate[] certificate_path;
    
    String[] endorsed_algorithms;

    String[] extension_types;
    
    
    public boolean isSymmetric ()
      {
        return is_symmetric_key;
      }
    
    public AppUsage getAppUsage () throws SKSException
      {
        for (AppUsage au : AppUsage.values ())
          {
            if (au.getSKSValue () == app_usage)
              {
                return au;
              }
          }
        throw new SKSException ("Internal AppUsage error");
      }
    
    public String getFriendlyName ()
      {
        return friendly_name;
      }

    public X509Certificate[] getCertificatePath ()
      {
        return certificate_path;
      }

    public String[] getEndorsedAlgorithms ()
      {
        return extension_types;
      }

    public String[] getExtensionTypes ()
      {
        return extension_types;
      }
    
    public KeyAttributes (boolean is_symmetric_key,
                          byte app_usage,
                          String friendly_name,
                          X509Certificate[] certificate_path,
                          String[] endorsed_algorithms,
                          String[] extension_types)
      {
        this.is_symmetric_key = is_symmetric_key;
        this.app_usage = app_usage;
        this.friendly_name = friendly_name;
        this.certificate_path = certificate_path;
        this.endorsed_algorithms = endorsed_algorithms;
        this.extension_types = extension_types;
      }
  }
