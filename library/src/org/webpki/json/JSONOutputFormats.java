/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

/**
 * JSON output types.
 * It is used by {@link JSONObjectWriter}.
 */
public enum JSONOutputFormats {

    NORMALIZED        (false, false, false),
    PRETTY_JS_NATIVE  (true,  true,  false),
    PRETTY_PRINT      (true,  false, false),
    PRETTY_HTML       (true,  false, true);

    boolean pretty;
    boolean javascript;
    boolean html;

    JSONOutputFormats(boolean pretty, boolean javascript, boolean html) {
        this.pretty = pretty;
        this.javascript = javascript;
        this.html = html;
    }

    public static String getOptions() {
        StringBuffer options = new StringBuffer();
        for (JSONOutputFormats format : JSONOutputFormats.values()) {
            if (options.length() > 0) {
                options.append('|');
            }
            options.append(format.toString());
        }
        return options.toString();
    }
}
