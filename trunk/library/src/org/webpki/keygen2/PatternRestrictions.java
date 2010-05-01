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


public enum PatternRestrictions
  {
    THREE_IN_A_ROW  ("three-in-a-row"),  // "111342" is bad
    SEQUENCE        ("sequence"),        // "abcdef" is bad
    MISSING_GROUP   ("missing-group");   // "13abc2" is bad for a "printable" PIN format (no ,.;!@ etc)

    private final String xml_name;       // As expressed in XML

    private PatternRestrictions (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static PatternRestrictions getPatternRestrictionFromString (String xml_name) throws IOException
      {
        for (PatternRestrictions restriction : PatternRestrictions.values ())
          {
            if (xml_name.equals (restriction.xml_name))
              {
                return restriction;
              }
          }
        throw new IOException ("Unknown pattern: " + xml_name);
      }

  }
