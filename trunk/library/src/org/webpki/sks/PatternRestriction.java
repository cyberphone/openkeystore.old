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
package org.webpki.sks;

import java.io.IOException;
import java.util.Set;

public enum PatternRestriction
  {
    TWO_IN_A_ROW    ("two-in-a-row",   (byte)0x01),    // "11342" is flagged
    THREE_IN_A_ROW  ("three-in-a-row", (byte)0x02),    // "111342" is flagged
    SEQUENCE        ("sequence",       (byte)0x04),    // "abcdef" is flagged
    REPEATED        ("repeated",       (byte)0x08),    // "abcdec" is flagged
    MISSING_GROUP   ("missing-group",  (byte)0x10);    // The PIN must be "alphanumeric" and contain a mix of
                                                       // letters, digits and punctuation characters 

    private final String xml_name;       // As expressed in XML
    
    private final byte sks_mask;         // As expressed in SKS

    private PatternRestriction (String xml_name, byte sks_mask)
      {
        this.xml_name = xml_name;
        this.sks_mask = sks_mask;
      }


    public String getXMLName ()
      {
        return xml_name;
      }
    
    
    public byte getSKSMaskBit ()
      {
        return sks_mask;
      }


    public static PatternRestriction getPatternRestrictionFromString (String xml_name) throws IOException
      {
        for (PatternRestriction restriction : PatternRestriction.values ())
          {
            if (xml_name.equals (restriction.xml_name))
              {
                return restriction;
              }
          }
        throw new IOException ("Unknown pattern: " + xml_name);
      }
    

    public static byte getSKSValue (Set<PatternRestriction> patterns)
      {
        byte result = 0;
        for (PatternRestriction pattern : patterns)
          {
            result |= pattern.sks_mask;
          }
        return result;
      }

  }
