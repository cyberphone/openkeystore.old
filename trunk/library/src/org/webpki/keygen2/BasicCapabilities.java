/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
import java.io.Serializable;

import java.util.Vector;
import java.util.LinkedHashSet;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.crypto.EncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;


public class BasicCapabilities implements Serializable
  {
    private static final long serialVersionUID = 1L;

    static final String BASIC_CAPABILITIES_ELEM = "BasicCapabilities";

    static final String SYMMETRIC_KEY_ENCRYPTION_ALGORITHMS_ATTR = "SymmetricKeyEncryptionAlgorithms";

    LinkedHashSet<SymEncryptionAlgorithms> sym_encryption_algorithms = new LinkedHashSet<SymEncryptionAlgorithms> ();

    String comment;
    

    static BasicCapabilities read (DOMReaderHelper rd) throws IOException
      {
        BasicCapabilities doc_data = new BasicCapabilities ();
        rd.getNext (BASIC_CAPABILITIES_ELEM);
        String[] opt_uri_list = rd.getAttributeHelper ().getListConditional (SYMMETRIC_KEY_ENCRYPTION_ALGORITHMS_ATTR);
        if (opt_uri_list != null) for (String algorithm_uri : opt_uri_list)
          {
            doc_data.sym_encryption_algorithms.add (SymEncryptionAlgorithms.getAlgorithmFromURI (algorithm_uri));
          }
        rd.getChild ();
        rd.getParent ();
        return doc_data;
      }


    void conditionalOutput (DOMWriterHelper wr, EncryptionAlgorithms[] algorithms, String tag)
      {
        if (algorithms.length > 0)
          {
            Vector<String> uris = new Vector<String> ();
            for (EncryptionAlgorithms alg : algorithms)
              {
                uris.add (alg.getURI ());
              }
            wr.setListAttribute (tag, uris.toArray (new String[0]));
          }
      }


    void write (DOMWriterHelper wr) throws IOException
      {
        wr.addChildElement (BASIC_CAPABILITIES_ELEM);

        if (comment != null)
          {
            wr.addComment (comment, true);
          }
        conditionalOutput (wr,
                           sym_encryption_algorithms.toArray (new EncryptionAlgorithms[0]), 
                           SYMMETRIC_KEY_ENCRYPTION_ALGORITHMS_ATTR);
        wr.getParent ();
      }


    public BasicCapabilities addSymmetricKeyEncryptionAlgorithm (SymEncryptionAlgorithms algorithm)
      {
        sym_encryption_algorithms.add (algorithm);
        return this;
      }

    public BasicCapabilities setComment (String comment)
      {
        this.comment = comment;
        return this;
      }


    public LinkedHashSet<SymEncryptionAlgorithms> getSymmetricKeyEncryptionAlgorithms () throws IOException
      {
        return sym_encryption_algorithms;
      }
  }
