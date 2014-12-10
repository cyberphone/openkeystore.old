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
package org.webpki.mobile.android.util;

import java.net.MalformedURLException;
import java.net.URL;

import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.SKSException;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.sks.SKSImplementation;

import android.content.Context;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;

public class CredentialListDataFactory
  {
    BitmapFactory.Options bmo;
    Bitmap default_icon;
    SKSImplementation sks;
    Context caller;

    public CredentialListDataFactory (Context caller, SKSImplementation sks)
      {
        this.sks = sks;
        this.caller = caller;
        bmo = new BitmapFactory.Options ();
        bmo.inScaled = false;
        default_icon = BitmapFactory.decodeResource (caller.getResources (), R.drawable.certview_logo_na, bmo);
        default_icon.setDensity (Bitmap.DENSITY_NONE);
      }
    
    public Bitmap getListIcon (int key_handle) throws SKSException
      {
        KeyAttributes key_attributes = sks.getKeyAttributes (key_handle);
        Bitmap issuer_bm = default_icon;
        for (String type : key_attributes.getExtensionTypes ())
          {
            if (type.equals (KeyGen2URIs.LOGOTYPES.LIST))
              {
                Extension extension = sks.getExtension (key_handle, type);
                issuer_bm = BitmapFactory.decodeByteArray (extension.getExtensionData (), 0, extension.getExtensionData ().length, bmo);
                issuer_bm.setDensity (Bitmap.DENSITY_NONE);
                issuer_bm = Bitmap.createScaledBitmap (issuer_bm, default_icon.getWidth (), default_icon.getHeight (), true);
                break;
              }
          }
        Bitmap derived_bm = BitmapFactory.decodeResource (caller.getResources (), R.drawable.credview_background_bm, bmo).copy (Bitmap.Config.ARGB_8888, true);
        derived_bm.setDensity (Bitmap.DENSITY_NONE);
        Canvas canvas = new Canvas (derived_bm);
        canvas.drawBitmap (issuer_bm, (derived_bm.getWidth() - issuer_bm.getWidth())/ 2, (derived_bm.getHeight() - issuer_bm.getHeight()) / 2, null);
        return derived_bm;
      }

    public String getDomain (int key_handle) throws SKSException, MalformedURLException
      {
        EnumeratedKey ek = new EnumeratedKey ();
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (key_handle == ek.getKeyHandle ())
              {
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
                  {
                    if (ek.getProvisioningHandle () == eps.getProvisioningHandle ())
                      {
                        return new URL (eps.getIssuerUri ()).getHost ();
                      }
                  }
              }
          }
        return "***ERROR***";
      }

    public String getFriendlyName (int key_handle) throws SKSException
      {
        return sks.getKeyAttributes (key_handle).getFriendlyName ();
      }
  }