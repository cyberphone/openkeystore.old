/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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

import org.webpki.sks.SecureKeyStore;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class BasicCapabilities
  {
    LinkedHashSet<String> algorithms = new LinkedHashSet<String> ();

    LinkedHashSet<String> features = new LinkedHashSet<String> ();

    LinkedHashSet<String> extensions = new LinkedHashSet<String> ();
    
    LinkedHashSet<Short> rsa_key_sizes = new LinkedHashSet<Short> ();
    
    boolean rsa_exponent_set;
    
    boolean rsa_exponent_settable;
    
    boolean rsa_key_size_set;

    String comment;
    
    BasicCapabilities ()
      {
        for (short key_size : SecureKeyStore.SKS_DEFAULT_RSA_SUPPORT)
          {
            rsa_key_sizes.add (key_size);
          }
      }
    
    
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


    static void read (DOMReaderHelper rd, LinkedHashSet<String> args, String tag) throws IOException
      {
        String[] opt_uri_list = rd.getAttributeHelper ().getListConditional (tag);
        if (opt_uri_list != null)
          {
            for (String uri : opt_uri_list)
              {
                args.add (uri);
              }
          }
      }

    static BasicCapabilities read (DOMReaderHelper rd) throws IOException
      {
        BasicCapabilities doc_data = new BasicCapabilities ();
        rd.getNext (BASIC_CAPABILITIES_ELEM);
        read (rd, doc_data.algorithms, ALGORITHMS_ATTR);
        read (rd, doc_data.features, FEATURES_ATTR);
        read (rd, doc_data.extensions, EXTENSIONS_ATTR);
        rd.getChild ();
        if (rd.hasNext ())
          {
            rd.getNext (RSA_SUPPORT_ELEM);
            for (String rsa : rd.getAttributeHelper ().getList (KEY_SIZES_ATTR))
              {
                doc_data.addRSAKeySize (new Short (rsa));
              }
            doc_data.rsa_exponent_settable = rd.getAttributeHelper ().getBooleanConditional (SETTABLE_EXPONENT_ATTR);

          }
        rd.getParent ();
        return doc_data;
      }


    void conditionalOutput (DOMWriterHelper wr, LinkedHashSet<String> arg_set, String tag)
      {
        if (!arg_set.isEmpty ())
          {
            wr.setListAttribute (tag, arg_set.toArray (new String[0]));
          }
      }


    void write (DOMWriterHelper wr) throws IOException
      {
        wr.addChildElement (BASIC_CAPABILITIES_ELEM);

        if (comment != null)
          {
            wr.addComment (comment, true);
          }
        conditionalOutput (wr,  algorithms, ALGORITHMS_ATTR);
        conditionalOutput (wr,  features, FEATURES_ATTR);
        conditionalOutput (wr,  extensions, EXTENSIONS_ATTR);
        if (rsa_exponent_set || rsa_key_size_set)
          {
            wr.addChildElement (RSA_SUPPORT_ELEM);
            if (rsa_exponent_set)
              {
                wr.setBooleanAttribute (SETTABLE_EXPONENT_ATTR, rsa_exponent_settable);
              }
            String[] sizes = new String[rsa_key_sizes.size ()];
            int i = 0;
            for (int size : rsa_key_sizes)
              {
                sizes[i++] = String.valueOf (size);
              }
            wr.setListAttribute (KEY_SIZES_ATTR, sizes);
          }
        wr.getParent ();
      }

    
    void add (LinkedHashSet<String> arg_set, String arg) throws IOException
      {
        if (!arg_set.add (arg))
          {
            throw new IOException ("Multiply defined argument: " + arg);
          }
      }


    public BasicCapabilities addAlgorithm (String algorithm) throws IOException
      {
        add (algorithms, algorithm);
        return this;
      }

    
    public BasicCapabilities addFeature (String feature) throws IOException
      {
        add (algorithms, feature);
        return this;
      }

    
    public BasicCapabilities addExtension (String extension) throws IOException
      {
        add (extensions, extension);
        return this;
      }


    public BasicCapabilities addRSAKeySize (short key_size) throws IOException
      {
        if (!rsa_key_size_set)
          {
            rsa_key_sizes.clear ();
            rsa_key_size_set = true;
          }
        if (!rsa_key_sizes.add (key_size))
          {
            throw new IOException ("Multiply defined key size:" + key_size);
          }
        return this;
      }


    public BasicCapabilities setRSAExponentSettable (boolean flag) throws IOException
      {
        rsa_exponent_set = true;
        rsa_exponent_settable = flag;
        return this;
      }


    public BasicCapabilities setComment (String comment)
      {
        this.comment = comment;
        return this;
      }


    public String[] getAlgorithms () throws IOException
      {
        return algorithms.toArray (new String[0]);
      }

    
    public String[] getFeatures () throws IOException
      {
        return features.toArray (new String[0]);
      }


    public String[] getExtensions () throws IOException
      {
        return extensions.toArray (new String[0]);
      }


    public short[] getRSAKeySizes () throws IOException
      {
        short[] sizes = new short[rsa_key_sizes.size ()];
        int i = 0;
        for (short key_size : rsa_key_sizes)
          {
            sizes[i++] = key_size;
          }
        return sizes;
      }


    public boolean getRSAExponentSettableFlag ()
      {
        return rsa_exponent_settable;
      }
 }
