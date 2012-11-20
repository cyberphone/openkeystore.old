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
import android.widget.LinearLayout;

public class KeyGen2InitLayout extends LinearLayout
  {
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
        getChildAt (3).setMinimumWidth (getChildAt (2).getMeasuredWidth());
        super.onMeasure (wSpec, hSpec);
        Log.i ("M2", "W=" + getMeasuredWidth());
        int w_max = getChildAt (0).getMeasuredWidth();
        if (w_max < getChildAt (1).getMeasuredWidth())
          {
            w_max = getChildAt (1).getMeasuredWidth();
          }
        int button_w = getChildAt (2).getMeasuredWidth();
        if (button_w > 0)
          {
            int height = 60 + getChildAt (0).getMeasuredHeight () + getChildAt (1).getMeasuredHeight () ;
            int width = 40 + w_max;
            if (w > h)
              {
                width += 40 + 2 * button_w;
                int up = getChildAt (2).getMeasuredHeight () -  getChildAt (1).getMeasuredHeight ();
                  {
                    if (up > 0)
                      {
                        height += up / 2 + getChildAt (2).getMeasuredHeight () / 12;
                      }
                  }
              }
            else
              {
                height += 20 + getChildAt (3).getMeasuredHeight ();
              }
            setMeasuredDimension (width, height);
//            getChildAt (4).setMinimumWidth (0);
//            getChildAt (4).setMinimumWidth (width);
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
        Log.i ("L", "C=" + changed + " L=" + l + " T=" + t + " R=" + r + " b=" + b);
//        super.onLayout (changed, l, t, r, b);
        // if( !changed ) return;
        int height = 0;
        int width = getChildAt (0).getMeasuredWidth ();
        getChildAt (0).layout ((r - l - width)/2, height + 20, (r - l - width)/2 + width, height + getChildAt (0).getMeasuredHeight () + 20);
        width = getChildAt (1).getMeasuredWidth ();
        getChildAt (1).layout ((r - l - width)/2, height + getChildAt (0).getMeasuredHeight () + 40, (r - l - width)/2 + width, height + getChildAt (0).getMeasuredHeight () + getChildAt (1).getMeasuredHeight () + 40);
        width = getChildAt (2).getMeasuredWidth ();
        getChildAt (2).layout (20, b - t - getChildAt (2).getMeasuredHeight () - 20, 20 + width , b - t - 20);
        getChildAt (3).layout (r - l - width - 20, b - t - getChildAt (3).getMeasuredHeight () - 20, r - l - 20 , b - t - 20);
        /*
        int len = getChildCount ();
        int top = 20;
        for (int i = 0; i < len; i++)
          {
            View c = getChildAt (i);
            int w = c.getMeasuredWidth ();
            int h = c.getMeasuredHeight ();
            c.layout (20, top , w + 20, top + h);
            top += 20 + h;
            Log.i ("CH2", "W=" + c.getWidth ());
          }
          */
      }
  }
