/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;

/**
 * Basic JSON types read by the parser.
 *
 */
public enum JSONTypes 
  {
    NULL (null),
    BOOLEAN (null),
    INTEGER (null),
    DECIMAL (new JSONTypes[]{INTEGER}),
    FLOATING_POINT (new JSONTypes[]{INTEGER, DECIMAL}),
    STRING (null),
    ARRAY (null),
    OBJECT (null);
    
    JSONTypes[] sub_types;  // Also accepted during "get"
    
    JSONTypes (JSONTypes[] sub_types)
      {
        this.sub_types = sub_types;
      }
    
    boolean isCompatible (JSONTypes actual)
      {
        boolean is_compatible = true;
        if (actual != this)
          {
            is_compatible = false;
            if (sub_types != null)
              {
                for (JSONTypes alt_type : sub_types)
                  {
                    if (alt_type == actual)
                      {
                        is_compatible = true;
                      }
                  }
              }
          }
        return is_compatible;
      }
  }
