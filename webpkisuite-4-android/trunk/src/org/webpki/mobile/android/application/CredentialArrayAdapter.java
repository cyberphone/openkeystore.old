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
package org.webpki.mobile.android.application;

import java.util.List;

import org.webpki.mobile.android.R;

import android.content.Context;

import android.graphics.Bitmap;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;

public class CredentialArrayAdapter extends ArrayAdapter<CredentialArrayAdapter.CredentialData>
  {
    private final Context context;
    private final List<CredentialData> values;

    public CredentialArrayAdapter (Context context, List<CredentialData> values)
      {
        super (context, R.layout.activity_credentials, values);
        this.context = context;
        this.values = values;
      }

    class ViewHolder
      {
        TextView issuer_domain;
        TextView subject_dn_or_friendly_name;
        ImageView icon;
      }

    static class CredentialData
      {
        private String domain;
        private String name;
        private int key_handle;
        Bitmap icon;

        public CredentialData (String domain, int key_handle, String name, Bitmap icon)
          {
            this.icon = icon;
            this.domain = domain;
            this.name = name;
            this.key_handle = key_handle;
          }

        public String getDomain ()
          {
            return domain;
          }

        public String getName ()
          {
            return name;
          }

        public int getKeyHandle ()
          {
            return key_handle;
          }

        public Bitmap getIcon ()
          {
            return icon;
          }
      }

    @Override
    public View getView (int position, View convertView, ViewGroup parent)
      {
        View rowView = null;
        if (convertView != null)
          {
            rowView = convertView;
          }
        else
          {
            LayoutInflater inflater = (LayoutInflater) context.getSystemService (Context.LAYOUT_INFLATER_SERVICE);
            rowView = inflater.inflate (R.layout.activity_credentials, parent, false);
            ViewHolder holder = new ViewHolder ();
            holder.issuer_domain = (TextView) rowView.findViewById (R.id.issuer_domain);
            holder.subject_dn_or_friendly_name = (TextView) rowView.findViewById (R.id.subject_dn_or_friendly_name);
            holder.icon = (ImageView) rowView.findViewById (R.id.icon);
            rowView.setTag (holder);
          }
        ViewHolder tag = (ViewHolder) rowView.getTag ();
        tag.issuer_domain.setText (values.get (position).getDomain ());
        tag.subject_dn_or_friendly_name.setText (values.get (position).getName ());
        tag.icon.setImageBitmap (values.get (position).getIcon ());
        return rowView;
      }
}