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
package org.webpki.mobile.android.proxy.keygen2;

import android.content.Context;

import android.util.AttributeSet;
import android.util.Log;

import android.widget.FrameLayout;

import static org.webpki.mobile.android.proxy.keygen2.KeyGen2InitLayout.PADDING;

public class KeyGen2PINLayout extends FrameLayout
  {
    static final int PIN_CHUNK = 0;
    static final int CANCEL_BUTTON = 1;
    static final int OK_BUTTON = 2;

    public KeyGen2PINLayout (Context context)
      {
        super (context);
      }

    public KeyGen2PINLayout (Context context, AttributeSet attrs)
      {
        super (context, attrs);
      }

    @Override
    protected void onMeasure (int wSpec, int hSpec)
      {
        int ws = MeasureSpec.getMode (wSpec);
        int w = MeasureSpec.getSize (wSpec);
        int hs = MeasureSpec.getMode (hSpec);
        int h = MeasureSpec.getSize (hSpec);
        super.onMeasure (wSpec, hSpec);
        int button_w = getChildAt (CANCEL_BUTTON).getMeasuredWidth();
        getChildAt (OK_BUTTON).setMinimumWidth (button_w);
        int button_h = getChildAt (CANCEL_BUTTON).getMeasuredHeight();
        int w_max = getChildAt (PIN_CHUNK).getMeasuredWidth();
        Log.e ("M", "PH=" + getChildAt (PIN_CHUNK).getMeasuredWidth() + " BW=" + button_w + " H=" + h);
//        if (button_w > 0)
          {
            int height = PADDING * 2 + getChildAt (PIN_CHUNK).getMeasuredHeight ();
            int width = PADDING * 2 + w_max;
            if (w > h)
              {
                width += 2 * (button_w + PADDING);
              }
            else
              {
                height += PADDING + button_h;
              }
            setMeasuredDimension (width, height);
          }
       }

    @Override
    protected void onLayout (boolean changed, int l, int t, int r, int b)
      {
        int width = getChildAt (PIN_CHUNK).getMeasuredWidth ();
        getChildAt (PIN_CHUNK).layout ((r - l - width)/2, PADDING, (r - l - width)/2 + width, getChildAt (PIN_CHUNK).getMeasuredHeight () + PADDING);
        width = getChildAt (CANCEL_BUTTON).getMeasuredWidth ();
        getChildAt (CANCEL_BUTTON).layout (PADDING, b - t - getChildAt (CANCEL_BUTTON).getMeasuredHeight () - PADDING, PADDING + width , b - t - PADDING);
        getChildAt (OK_BUTTON).layout (r - l - width - PADDING, b - t - getChildAt (OK_BUTTON).getMeasuredHeight () - PADDING, r - l - PADDING , b - t - PADDING);
      }
  }

