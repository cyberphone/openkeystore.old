/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.proxy;

import android.content.Context;

import android.util.AttributeSet;

import android.widget.Button;

/**
 * Specific Button class o make OK=Cancel wrt width.
 */
public class MatchedButton extends Button
  {
    // This constructor is used by LayoutInflater
    public MatchedButton (Context context, AttributeSet attrs)
      {
        super (context, attrs);
      }
    
    public int match (MatchedButton the_other_button)
      {
        MatchedButton fat_one = this;
        if (getMeasuredWidth () < the_other_button.getMeasuredWidth ())
          {
            fat_one = the_other_button;
            the_other_button = this;
          }
        int width = fat_one.getMeasuredWidth ();
        the_other_button.setMeasuredDimension (width, getMeasuredHeight ());
        the_other_button.setMinimumWidth (width);
        return width;
      }
  }
