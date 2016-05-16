/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.saturn;

import android.content.Context;

import android.text.InputType;

import android.util.AttributeSet;

import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;

import android.webkit.WebView;

public class SaturnView extends WebView {
    
    boolean numbericPin;

    public SaturnView(Context context) {
        super(context);
    }

    public SaturnView(Context context, AttributeSet attrs) {
       super(context, attrs);
    }

    public SaturnView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    @Override
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        InputConnection inputConnection = super.onCreateInputConnection(outAttrs);
        if (numbericPin) {
            outAttrs.inputType = InputType.TYPE_NUMBER_VARIATION_PASSWORD | InputType.TYPE_CLASS_NUMBER;
        }
        return inputConnection; 
    }
}
