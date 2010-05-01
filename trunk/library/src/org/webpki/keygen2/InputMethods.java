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


public enum InputMethods
  {
    ANY           ("any"),
    PROGRAMMATIC  ("programmatic"),
    TRUSTED_GUI   ("trusted-gui");

    private final String xml_name;       // As expressed in XML

    private InputMethods (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static InputMethods getMethodFromString (String xml_name) throws IOException
      {
        for (InputMethods type : InputMethods.values ())
          {
            if (xml_name.equals (type.xml_name))
              {
                return type;
              }
          }
        throw new IOException ("Unknown method: " + xml_name);
      }

  }
