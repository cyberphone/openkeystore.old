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

import java.util.ArrayList;
import java.util.List;


import org.webpki.android.sks.EnumeratedKey;
import org.webpki.android.sks.KeyAttributes;
import org.webpki.android.sks.SKSException;

import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

import org.webpki.mobile.android.util.CredentialListDataFactory;

import android.os.Bundle;

import android.view.ContextMenu;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ContextMenu.ContextMenuInfo;

import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import android.app.AlertDialog;
import android.app.ListActivity;

import android.content.DialogInterface;
import android.content.Intent;

import android.graphics.drawable.BitmapDrawable;

public class CredentialsActivity extends ListActivity
  {
    private static final String DIALOG = "Dialog";
    
    SKSImplementation sks = SKSStore.createSKS (DIALOG, getBaseContext (), true);

    List<CredentialArrayAdapter.CredentialData> list = new ArrayList<CredentialArrayAdapter.CredentialData> ();
    
    private void serializeSKS ()
      {
        SKSStore.serializeSKS (DIALOG, getBaseContext ());
      }

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        try
          {
            CredentialListDataFactory credential_data_factory = new CredentialListDataFactory (this, sks);
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                list.add (new CredentialArrayAdapter.CredentialData (credential_data_factory.getDomain (ek.getKeyHandle ()), 
                                                                     ek.getKeyHandle (),
                                                                     ka.getFriendlyName () == null ?
                                            ka.getCertificatePath ()[0].getSubjectDN ().getName () : ka.getFriendlyName (),
                                                                     credential_data_factory.getListIcon (ek.getKeyHandle ())));
              }
            setListAdapter (new CredentialArrayAdapter (this, list));
            registerForContextMenu (getListView ());
          }
        catch (Exception e)
          {
            throw new RuntimeException (e);
          }
      }

    
    @Override
    protected void onListItemClick (ListView l, View view, int position, long id)
      {
        view.showContextMenu();
      }

    @Override
    public void onCreateContextMenu (ContextMenu menu, View v, ContextMenuInfo menuInfo)
      {
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) menuInfo;
        menu.setHeaderTitle (list.get (info.position).getDomain ());
        menu.setHeaderIcon (new BitmapDrawable (getResources (), list.get (info.position).getIcon ()));
        // String[] menuItems = getResources().getStringArray(R.array.menu);
        String[] menuItems = { "Certificate Properties", "Additional Properties", "Clear Grants", "Delete Credential" };
        for (int i = 0; i < menuItems.length; i++)
          {
            menu.add (Menu.NONE, i, i, menuItems[i]);
          }
      }
    

    @SuppressWarnings("unchecked")
    @Override
    public boolean onContextItemSelected (MenuItem item)
      {
        final AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo ();
        int menuItemIndex = item.getItemId ();
         if (menuItemIndex == 0)
          {
            try
              {
                Intent intent = new Intent (this, CertificateViewActivity.class);
                intent.putExtra (CertificateViewActivity.CERTIFICATE_BLOB, 
                                 sks.getKeyAttributes (list.get (info.position).getKeyHandle ()).getCertificatePath ()[0].getEncoded ());
                startActivity (intent);
              }
            catch (Exception e)
              {
                throw new RuntimeException (e);
              }
          }
        else if (menuItemIndex == 1)
          {
            Toast.makeText (getApplicationContext (), "Not Implemented!", Toast.LENGTH_LONG).show ();
          }
        else if (menuItemIndex == 2)
          {
            try
              {
                int key_handle = list.get (info.position).getKeyHandle ();
                int i = 0;
                for (String domain : sks.listGrants (key_handle))
                  {
                    i++;
                    sks.setGrant (key_handle, domain, false);
                  }
                Toast.makeText (getApplicationContext (), String.valueOf (i) + " granted domains cleared", Toast.LENGTH_LONG).show ();
                serializeSKS ();
              }
            catch (Exception e)
              {
                throw new RuntimeException (e);
              }
          }
        else
          {
            AlertDialog.Builder alert_dialog = 
                new AlertDialog.Builder (this).setIcon (new BitmapDrawable (getResources (), list.get (info.position).getIcon ()))
                    .setTitle (list.get (info.position).getDomain ())
                    .setMessage ("Do you want to delete this credential?")
                    .setPositiveButton ("Yes", new DialogInterface.OnClickListener ()
              {
                public void onClick (DialogInterface dialog, int id)
                  {
                    // The user decided that this credential should be deleted...
                    try
                      {
                        sks.deleteKey (list.get (info.position).getKeyHandle (), null);
                        list.remove (info.position);
                        ((ArrayAdapter<CredentialArrayAdapter.CredentialData>) getListAdapter ()).notifyDataSetChanged ();
                        dialog.cancel ();
                        serializeSKS ();
                      }
                    catch (SKSException e)
                      {
                        Toast.makeText (getApplicationContext (), "Not permitted: " + e.getMessage (), Toast.LENGTH_LONG).show ();
                      }
                  }
              });
            alert_dialog.setNegativeButton ("No", new DialogInterface.OnClickListener ()
              {
                public void onClick (DialogInterface dialog, int id)
                  {
                    // The user apparently changed his/her mind and wants to continue...
                    dialog.cancel ();
                  }
              });
            alert_dialog.create ().show ();
          }
        return true;
      }
   }