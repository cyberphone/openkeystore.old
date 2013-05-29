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

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.webpki.android.keygen2.KeyGen2URIs;
import org.webpki.android.sks.EnumeratedKey;
import org.webpki.android.sks.EnumeratedProvisioningSession;
import org.webpki.android.sks.Extension;
import org.webpki.android.sks.KeyAttributes;
import org.webpki.android.sks.SKSException;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

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

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;

public class CredentialsActivity extends ListActivity
  {
    SKSImplementation sks = SKSStore.createSKS ("Dialog", getBaseContext (), true);

    List<CredentialArrayAdapter.CredentialData> list = new ArrayList<CredentialArrayAdapter.CredentialData> ();
    
    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        try
          {
            BitmapFactory.Options bmo = new BitmapFactory.Options ();
            bmo.inScaled = false;
            Bitmap default_icon = BitmapFactory.decodeResource (getResources (), R.drawable.certview_logo_na, bmo);
            default_icon.setDensity (Bitmap.DENSITY_NONE);

            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                String domain = "***ERROR***";
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
                  {
                    if (ek.getProvisioningHandle () == eps.getProvisioningHandle ())
                      {
                        domain = new URL (eps.getIssuerURI ()).getHost ();
                        break;
                      }
                  }
                KeyAttributes key_attributes = sks.getKeyAttributes (ek.getKeyHandle ());
                Bitmap issuer_bm = default_icon;
                for (String type : key_attributes.getExtensionTypes ())
                  {
                    if (type.equals (KeyGen2URIs.LOGOTYPES.LIST))
                      {
                        Extension extension = sks.getExtension (ek.getKeyHandle (), type);
                        issuer_bm = BitmapFactory.decodeByteArray (extension.getExtensionData (), 0, extension.getExtensionData ().length, bmo);
                        issuer_bm.setDensity (Bitmap.DENSITY_NONE);
                        issuer_bm = Bitmap.createScaledBitmap (issuer_bm, default_icon.getWidth (), default_icon.getHeight (), true);
                        break;
                      }
                  }
                Bitmap derived_bm = BitmapFactory.decodeResource (getResources (), R.drawable.credview_background_bm, bmo).copy (Bitmap.Config.ARGB_8888, true);
                derived_bm.setDensity (Bitmap.DENSITY_NONE);
                Canvas canvas = new Canvas (derived_bm);
                canvas.drawBitmap (issuer_bm, (derived_bm.getWidth() - issuer_bm.getWidth())/ 2, (derived_bm.getHeight() - issuer_bm.getHeight()) / 2, null);
                list.add (new CredentialArrayAdapter.CredentialData (domain, 
                                                                     ek.getKeyHandle (),
                                                                     key_attributes.getCertificatePath ()[0].getSubjectDN ().getName (),
                                                                     derived_bm));
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
        String[] menuItems = { "Certificate Properties", "Additional Properties", "Delete Credential" };
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
                Intent intent = new Intent (this, CertViewActivity.class);
                intent.putExtra (CertViewActivity.CERTIFICATE_BLOB, 
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