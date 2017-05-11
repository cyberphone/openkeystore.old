/*
 *  Copyright 2006-2017 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.testdata;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/*
 * Holder if symmetric keys
 */
public class SymmetricKeys {
    public byte[] s128bitkey;
    public byte[] s256bitkey;
    public byte[] s384bitkey;
    public byte[] s512bitkey;
    
    JSONObjectReader symmetricKeys;
  
    SymmetricKeys(String keyBase) throws Exception {
        symmetricKeys = JSONParser.parse(ArrayUtil.readFile(keyBase + "symmetrickeys.json"));
        s128bitkey = getValue(128);
        s256bitkey = getValue(256);
        s384bitkey = getValue(384);
        s512bitkey = getValue(512);
        symmetricKeys.checkForUnread();
    }
    
    String getName(int i) {
        return "s" + i + "bitkey";
    }
    
    byte[] getValue(int i) throws Exception {
        byte[] key = symmetricKeys.getBinary(getName(i));
        if (key.length * 8 != i) {
            throw new Exception("Bad sym key:" + key.length);
        }
        return key;
    }
}