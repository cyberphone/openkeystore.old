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
package org.webpki.mobile.android.proxy;

import android.os.Bundle;

import android.view.View;

import android.widget.ArrayAdapter;
import android.widget.ListView;

import android.app.ListActivity;

public class SettingsActivity extends ListActivity
  {
    String[] items = { "this", "is", "a", "really", 
        "silly", "list" };

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
              super.onCreate(savedInstanceState);
              setContentView(R.layout.activity_settings);
       setListAdapter(new ArrayAdapter<String>(
             this,
             android.R.layout.simple_expandable_list_item_1,
             items));
          }

       @Override
       protected void onListItemClick(ListView l, View v, int position, long id) {
       super.onListItemClick(l, v, position, id);
       String text = " position:" + position + "  " + items[position];
       android.util.Log.i ("YEA", text);
       }
             
   }
