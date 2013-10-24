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
package org.webpki.mobile.android.application;

import org.webpki.android.crypto.DeviceID;

import org.webpki.android.sks.SKSException;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.keygen2.KeyGen2Activity;
import org.webpki.mobile.android.webauth.WebAuthActivity;

import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

import android.os.Bundle;

import android.view.ContextMenu;
import android.view.MenuItem;
import android.view.View;

import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ListActivity;

import android.content.DialogInterface;
import android.content.Intent;

public class PropertiesActivity extends ListActivity
  {
    static final int SETTINGS_ABOUT = 0;
    static final int SETTINGS_DEVICE_ID = 1;
    static final int SETTINGS_USER_CREDENTIALS = 2;
    static final int SETTINGS_DEVICE_CERT = 3;
    static final int SETTINGS_EXT_DEVICE_ID = 4;
    static final int SETTINGS_PROTOCOL_LOG = 5;
    String[] items = { "About", 
                       "Device ID",
                       "User Credentials",
                       "Device Certificate",
                       "Extended Device ID",
                       "Show Protocol Log"};
    SKSImplementation sks;

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_properties);
        setListAdapter (new ArrayAdapter<String> (this, android.R.layout.simple_list_item_1, items));
        registerForContextMenu (getListView ());
      }

    @SuppressWarnings("deprecation")
    @Override
    protected void onListItemClick (ListView l, View v, int position, long id)
      {
        super.onListItemClick (l, v, position, id);
        sks = SKSStore.createSKS ("Dialog", getBaseContext (), true);
        if (id == SETTINGS_DEVICE_CERT)
          {
            Intent intent = new Intent (this, CertificateViewActivity.class);
            try
              {
                intent.putExtra (CertificateViewActivity.CERTIFICATE_BLOB, sks.getDeviceInfo ().getCertificatePath ()[0].getEncoded ());
              }
            catch (Exception e)
              {
                intent.putExtra (CertificateViewActivity.CERTIFICATE_BLOB, new byte[]{});
              }
            startActivity (intent);
          }
        else if (id == SETTINGS_USER_CREDENTIALS)
          {
            try
              {
                if (sks.enumerateKeys (0) != null)
                  {
                    Intent intent = new Intent (this, CredentialsActivity.class);
                    startActivity (intent);
                    return;
                  }
              }
            catch (SKSException e)
              {
              }
            showDialog (position);
          }
        else if (id == SETTINGS_PROTOCOL_LOG)
          {
            super.onListItemClick(l, v, position, id); 
            v.showContextMenu ();            
          }
        else
          {
            showDialog (position);
          }
      }

    @Override
    public void onCreateContextMenu (ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo)
      {
         if (((AdapterView.AdapterContextMenuInfo)menuInfo).position == SETTINGS_PROTOCOL_LOG)
           {
             menu.setHeaderTitle ("Show last run with:");
             menu.add (KeyGen2Activity.KEYGEN2);
             menu.add (WebAuthActivity.WEBAUTH);
           }
      }    

    @Override
    public boolean onContextItemSelected (MenuItem item)
      {
        Intent intent = new Intent (this, ProtocolViewActivity.class);
        intent.putExtra (ProtocolViewActivity.LOG_FILE, item.getTitle ());
        startActivity (intent);
        return true;
      }

    @Override
    protected Dialog onCreateDialog (int id)
      {
        switch (id)
          {
            case SETTINGS_ABOUT:
              AlertDialog.Builder about_builder = new AlertDialog.Builder (this);
              about_builder.setTitle ("About");
              String version ="??";
            try
              {
                version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
              }
            catch (Exception e)
              {
              }
              about_builder.setMessage ("This application was developed by PrimeKey Solutions AB.\n\nCurrent version: " + version);
              about_builder.setIcon (android.R.drawable.btn_star_big_on);
              about_builder.setPositiveButton (android.R.string.ok, new DialogInterface.OnClickListener ()
                {
                  public void onClick (DialogInterface dialog, int which)
                    {
                      return;
                    }
                });
              return about_builder.create ();

            case SETTINGS_DEVICE_ID:
              AlertDialog.Builder device_id_builder = new AlertDialog.Builder (this);
              device_id_builder.setTitle ("Device ID");
              device_id_builder.setIcon (android.R.drawable.ic_menu_info_details);
              try
                {
                  StringBuffer devid = new StringBuffer (DeviceID.getDeviceID (sks.getDeviceInfo ().getCertificatePath ()[0], false));
                  for (int i = 0, j = 4; i < 4; i++, j += 5)
                    {
                      devid.insert (j, '-');
                    }
                  device_id_builder.setMessage (devid);
                }
              catch (SKSException e)
                {
                  device_id_builder.setMessage ("Something went wrong");
                }
              device_id_builder.setPositiveButton (android.R.string.ok, new DialogInterface.OnClickListener ()
                {
                  public void onClick (DialogInterface dialog, int which)
                    {
                      return;
                    }
                });
              return device_id_builder.create ();
              
            case SETTINGS_USER_CREDENTIALS:
              AlertDialog.Builder no_credentials_alert = new AlertDialog.Builder (this);
              no_credentials_alert.setTitle ("User Credentials");
              no_credentials_alert.setIcon (android.R.drawable.ic_menu_info_details);
              no_credentials_alert.setMessage ("You have no credentials yet");
              no_credentials_alert.setPositiveButton (android.R.string.ok, new DialogInterface.OnClickListener ()
                {
                  public void onClick (DialogInterface dialog, int which)
                    {
                      return;
                    }
                });
              return no_credentials_alert.create ();
              
            default:
              Toast.makeText (getApplicationContext(), "Not implemented!", Toast.LENGTH_SHORT).show ();
          }
        return null;
      }
  }