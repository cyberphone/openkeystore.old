/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;

import java.util.Vector;

import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.webpki.util.ArrayUtil;

/**
 * Base class for java classes who can be translated from JSON data.
 *
 */
public abstract class JSONReaderHelper
  {

    public String getString (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public boolean getBooleanConditional (String name)
      {
        // TODO Auto-generated method stub
        return false;
      }

    public boolean hasNext (String name)
      {
        // TODO Auto-generated method stub
        return false;
      }

    public byte[] getBinary (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public void getNext (String name)
      {
        // TODO Auto-generated method stub

      }

    public boolean hasNext ()
      {
        // TODO Auto-generated method stub
        return false;
      }

    public void getParent ()
      {
        // TODO Auto-generated method stub

      }

    public void getChild ()
      {
        // TODO Auto-generated method stub

      }

    public String getStringConditional (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public int getInt (String name)
      {
        // TODO Auto-generated method stub
        return 0;
      }

    public byte[] getBinaryConditional (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public String getStringConditional (String name, String default_value)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public String[] getListConditional (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public boolean getBooleanConditional (String name, boolean default_value)
      {
        // TODO Auto-generated method stub
        return false;
      }

    public String[] getList (String name)
      {
        // TODO Auto-generated method stub
        return null;
      }
  }
