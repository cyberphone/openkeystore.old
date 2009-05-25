/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.xerces.dom;

import java.util.Vector;

import org.w3c.dom.DOMStringList;

/**
 * DOM Level 3
 * 
 * This class implements the DOM Level 3 Core interface DOMStringList.
 * 
 * @xerces.internal
 * 
 * @author Neil Delima, IBM
 */
public class DOMStringListImpl implements DOMStringList {
	
	//A collection of DOMString values
    private Vector fStrings;

    /** 
     * Construct an empty list of DOMStringListImpl
     */ 
    public DOMStringListImpl() {
        fStrings = new Vector();    
    }

    /** 
     * Construct an empty list of DOMStringListImpl
     */ 
    public DOMStringListImpl(Vector params) {
        fStrings = params;    
    }
        
	/**
	 * @see org.w3c.dom.DOMStringList#item(int)
	 */
	public String item(int index) {
        try {
            return (String) fStrings.elementAt(index);
        } catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
	}

	/**
	 * @see org.w3c.dom.DOMStringList#getLength()
	 */
	public int getLength() {
		return fStrings.size();
	}

	/**
	 * @see org.w3c.dom.DOMStringList#contains(String)
	 */
	public boolean contains(String param) {
		return fStrings.contains(param) ;
	}

    /**
     * DOM Internal:
     * Add a <code>DOMString</code> to the list.
     * 
     * @param param A string to add to the list
     */
    public void add(String param) {
        fStrings.add(param);
    }

}
