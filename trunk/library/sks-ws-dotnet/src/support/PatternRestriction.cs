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
namespace org.webpki.sks.ws.client
{
    using System;
    using System.Collections.Generic;
    
    [Flags]
    public enum PatternRestriction : sbyte
    {
        TWO_IN_A_ROW   = 0x01,    // "11342" is flagged
        THREE_IN_A_ROW = 0x02,    // "111342" is flagged
        SEQUENCE       = 0x04,    // "abcdef" is flagged
        REPEATED       = 0x08,    // "abcdec" is flagged
        MISSING_GROUP  = 0x10     // The PIN must be "alphanumeric" and contain a mix of
                                  // letters, digits and punctuation characters 
    }
    
    internal class _PatternRestrictions
    {
        public static HashSet<PatternRestriction> convert (sbyte flags)
        {
            HashSet<PatternRestriction> pr = new HashSet<PatternRestriction> ();
            foreach(sbyte b in Enum.GetValues(typeof(PatternRestriction)))
            {
                if ((b & flags) != 0)
                {
                    pr.Add ((PatternRestriction) b);
                }
            }
            return pr;
        }
    }
}