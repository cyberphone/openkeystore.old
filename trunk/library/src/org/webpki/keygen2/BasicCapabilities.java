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
package org.webpki.keygen2;

import java.io.IOException;

import java.util.LinkedHashSet;

import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;

public abstract class BasicCapabilities extends XMLObjectWrapper
  {
    LinkedHashSet<String> algorithms = new LinkedHashSet<String> ();

    LinkedHashSet<String> client_attributes = new LinkedHashSet<String> ();

    LinkedHashSet<String> extensions = new LinkedHashSet<String> ();
    
    
    static String[] getSortedAlgorithms (String[] algorithms) throws IOException
      {
        int i = 0;
        while (true)
          {
            if (i < (algorithms.length - 1))
              {
                if (algorithms[i].compareTo (algorithms[i + 1]) > 0)
                  {
                    String s = algorithms[i];
                    algorithms[i] = algorithms[i + 1];
                    algorithms[i + 1] = s;
                    i = 0;
                  }
                else
                  {
                    i++;
                  }
              }
            else
              {
                break;
              }
          }
        return algorithms;
      }


    static void conditionalInput (DOMAttributeReaderHelper ah, LinkedHashSet<String> args, String tag) throws IOException
      {
        String[] opt_uri_list = ah.getListConditional (tag);
        if (opt_uri_list != null)
          {
            for (String uri : opt_uri_list)
              {
                args.add (uri);
              }
          }
      }

    void readBasicCapabilities (DOMAttributeReaderHelper ah) throws IOException
      {
        conditionalInput (ah, algorithms, ALGORITHMS_ATTR);
        conditionalInput (ah, client_attributes, CLIENT_ATTRIBUTES_ATTR);
        conditionalInput (ah, extensions, EXTENSIONS_ATTR);
      }


    void conditionalOutput (DOMWriterHelper wr, LinkedHashSet<String> arg_set, String tag)
      {
        if (!arg_set.isEmpty ())
          {
            wr.setListAttribute (tag, arg_set.toArray (new String[0]));
          }
      }


    void writeBasicCapabilities (DOMWriterHelper wr) throws IOException
      {
        conditionalOutput (wr,  algorithms, ALGORITHMS_ATTR);
        conditionalOutput (wr,  client_attributes, CLIENT_ATTRIBUTES_ATTR);
        conditionalOutput (wr,  extensions, EXTENSIONS_ATTR);
      }

    
    void addCapability (LinkedHashSet<String> arg_set, String arg) throws IOException
      {
        if (!arg_set.add (arg))
          {
            throw new IOException ("Multiply defined argument: " + arg);
          }
      }


    public BasicCapabilities addAlgorithm (String algorithm) throws IOException
      {
        addCapability (algorithms, algorithm);
        return this;
      }

    
    public BasicCapabilities addClientAttribute (String client_attribute) throws IOException
      {
        addCapability (client_attributes, client_attribute);
        return this;
      }

    
    public BasicCapabilities addExtension (String extension) throws IOException
      {
        addCapability (extensions, extension);
        return this;
      }


   public String[] getAlgorithms () throws IOException
      {
        return algorithms.toArray (new String[0]);
      }

    
    public String[] getClientAttributes () throws IOException
      {
        return client_attributes.toArray (new String[0]);
      }


    public String[] getExtensions () throws IOException
      {
        return extensions.toArray (new String[0]);
      }
  }
