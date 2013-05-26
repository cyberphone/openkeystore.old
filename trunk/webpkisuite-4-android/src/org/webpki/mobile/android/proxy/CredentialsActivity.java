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

import java.util.Vector;

import org.webpki.android.crypto.DeviceID;

import org.webpki.android.sks.EnumeratedKey;

import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

import android.os.Bundle;

import android.view.View;

import android.widget.ArrayAdapter;
import android.widget.ListView;

import android.app.ListActivity;
import android.content.Intent;

public class CredentialsActivity extends ListActivity
  {
    SKSImplementation sks = SKSStore.createSKS ("Dialog", getBaseContext (), true);

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_credentials);
        Vector<String> items = new Vector<String> ();
        try
          {
            EnumeratedKey ek = sks.enumerateKeys (0);
            items.add (sks.getKeyAttributes (ek.getKeyHandle ()).getCertificatePath ()[0].getSubjectDN ().getName ().substring (0, 10));
          }
        catch (Exception e)
          {
            items.add ("Total fuck up");
          }
        setListAdapter (new ArrayAdapter<String> (this, android.R.layout.simple_expandable_list_item_1, items.toArray (new String[0])));
      }

    @Override
    protected void onListItemClick (ListView l, View v, int position, long id)
      {
        super.onListItemClick (l, v, position, id);
        Intent intent = new Intent (this, CertViewActivity.class);
        try
          {
            EnumeratedKey ek = sks.enumerateKeys (0);
            intent.putExtra (CertViewActivity.CERTIFICATE_BLOB, sks.getKeyAttributes (ek.getKeyHandle ()).getCertificatePath ()[0].getEncoded ());
          }
        catch (Exception e)
          {
            intent.putExtra (CertViewActivity.CERTIFICATE_BLOB, new byte[]{});
          }
        startActivity (intent);
      }
  }