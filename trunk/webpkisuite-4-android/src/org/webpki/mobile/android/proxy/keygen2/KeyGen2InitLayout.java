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
import android.view.View;
import android.widget.FrameLayout;

public class KeyGen2InitLayout extends FrameLayout
  {
    static final int PADDING = 20;

    static final int HOST_IMAGE = 0;
    static final int ACCEPT_TEXT = 1;
    static final int CANCEL_BUTTON = 2;
    static final int OK_BUTTON = 3;
    
    public KeyGen2InitLayout (Context context)
      {
        super (context);
      }

    public KeyGen2InitLayout (Context context, AttributeSet attrs)
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
        Log.i ("M", "WS=" + ws + " W=" + w + " HS=" + hs + " H=" + h);
        super.onMeasure (wSpec, hSpec);
        getChildAt (OK_BUTTON).setMinimumWidth (getChildAt (CANCEL_BUTTON).getMeasuredWidth());
        Log.i ("M2", "W=" + getMeasuredWidth());
        int w_max = getChildAt (HOST_IMAGE).getMeasuredWidth();
        if (w_max < getChildAt (ACCEPT_TEXT).getMeasuredWidth())
          {
            w_max = getChildAt (ACCEPT_TEXT).getMeasuredWidth();
          }
        int button_w = getChildAt (CANCEL_BUTTON).getMeasuredWidth();
        if (button_w > 0)
          {
            int height = PADDING * 3 + getChildAt (HOST_IMAGE).getMeasuredHeight () + getChildAt (ACCEPT_TEXT).getMeasuredHeight () ;
            int width = PADDING * 2 + w_max;
            if (w > h)
              {
                width += 2 * (button_w + PADDING);
                int up = getChildAt (CANCEL_BUTTON).getMeasuredHeight () -  getChildAt (ACCEPT_TEXT).getMeasuredHeight ();
                  {
                    if (up > 0)
                      {
                        height += up / 2 + getChildAt (CANCEL_BUTTON).getMeasuredHeight () / 12;
                      }
                  }
              }
            else
              {
                height += PADDING + getChildAt (OK_BUTTON).getMeasuredHeight ();
              }
            setMeasuredDimension (width, height);
            Log.i ("CHN", "W=" + getMeasuredWidth ());
          }
        int len = getChildCount ();
        for (int i = 0; i < len; i++)
          {
            View c = getChildAt (i);
            Log.i ("CH1", "W=" + c.getMeasuredWidth ());
          }
       }

    @Override
    protected void onLayout (boolean changed, int l, int t, int r, int b)
      {
        int height = 0;
        int width = getChildAt (HOST_IMAGE).getMeasuredWidth ();
        getChildAt (HOST_IMAGE).layout ((r - l - width)/2, height + PADDING, (r - l - width)/2 + width, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + PADDING);
        width = getChildAt (ACCEPT_TEXT).getMeasuredWidth ();
        getChildAt (ACCEPT_TEXT).layout ((r - l - width)/2, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + PADDING * 2, (r - l - width)/2 + width, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + getChildAt (ACCEPT_TEXT).getMeasuredHeight () + PADDING * 2);
        width = getChildAt (CANCEL_BUTTON).getMeasuredWidth ();
        getChildAt (CANCEL_BUTTON).layout (PADDING, b - t - getChildAt (CANCEL_BUTTON).getMeasuredHeight () - PADDING, PADDING + width , b - t - PADDING);
        getChildAt (OK_BUTTON).layout (r - l - width - PADDING, b - t - getChildAt (OK_BUTTON).getMeasuredHeight () - PADDING, r - l - PADDING , b - t - PADDING);
      }
  }
