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
package org.webpki.mobile.android.keygen2;

import org.webpki.mobile.android.proxy.MatchedButton;

import android.content.Context;

import android.util.AttributeSet;

import android.widget.FrameLayout;

public class KeyGen2InitLayout extends FrameLayout
  {
    public static final int PADDING = 20;

    static final int HOST_IMAGE    = 0;
    static final int ACCEPT_TEXT   = 1;
    static final int CANCEL_BUTTON = 2;
    static final int OK_BUTTON     = 3;

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
        int w = MeasureSpec.getSize (wSpec);
        int h = MeasureSpec.getSize (hSpec);
        boolean redo = getChildAt (CANCEL_BUTTON).getMeasuredHeight () == 0;
        super.onMeasure (wSpec, hSpec);
        int button_w = ((MatchedButton) getChildAt (CANCEL_BUTTON)).match ((MatchedButton) getChildAt (OK_BUTTON));
        if (redo)
          {
            super.onMeasure (wSpec, hSpec);
          }
        int button_h = getChildAt (CANCEL_BUTTON).getMeasuredHeight ();
        int w_max = getChildAt (HOST_IMAGE).getMeasuredWidth ();
        if (w_max < getChildAt (ACCEPT_TEXT).getMeasuredWidth ())
          {
            w_max = getChildAt (ACCEPT_TEXT).getMeasuredWidth ();
          }
        int height = PADDING * 3 + getChildAt (HOST_IMAGE).getMeasuredHeight () + getChildAt (ACCEPT_TEXT).getMeasuredHeight ();
        int width = PADDING * 2 + w_max;
        if (width > w)
          {
            width = w;
          }
        if (w > h && h < (height + PADDING * 2 + 2 * button_h))
          {
            width += 2 * (button_w + PADDING);
            int up = button_h - getChildAt (ACCEPT_TEXT).getMeasuredHeight ();
              {
                if (up > 0)
                  {
                    height += up / 2 + button_h / 12;
                  }
              }
          }
        else
          {
            height += PADDING + button_h;
          }
        setMeasuredDimension (width, height);
      }

    @Override
    protected void onLayout (boolean changed, int l, int t, int r, int b)
      {
        int height = 0;
        int width = getChildAt (HOST_IMAGE).getMeasuredWidth ();
        getChildAt (HOST_IMAGE).layout ((r - l - width) / 2, height + PADDING + 5, (r - l - width) / 2 + width, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + PADDING + 5);
        width = getChildAt (ACCEPT_TEXT).getMeasuredWidth ();
        getChildAt (ACCEPT_TEXT).layout ((r - l - width) / 2, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + PADDING * 2, (r - l - width) / 2 + width, height + getChildAt (HOST_IMAGE).getMeasuredHeight () + getChildAt (ACCEPT_TEXT).getMeasuredHeight () + PADDING * 2);
        width = getChildAt (CANCEL_BUTTON).getMeasuredWidth ();
        getChildAt (CANCEL_BUTTON).layout (PADDING, b - t - getChildAt (CANCEL_BUTTON).getMeasuredHeight () - PADDING, PADDING + width, b - t - PADDING);
        getChildAt (OK_BUTTON).layout (r - l - width - PADDING, b - t - getChildAt (OK_BUTTON).getMeasuredHeight () - PADDING, r - l - PADDING, b - t - PADDING);
      }
  }
