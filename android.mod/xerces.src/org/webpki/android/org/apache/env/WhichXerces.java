/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights 
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:  
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Xalan" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written 
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 2001, International
 * Business Machines Corporation., http://www.ibm.com.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */
package org.webpki.android.org.apache.env;

import java.lang.reflect.Field;

import java.util.Hashtable;

/**
 * Get Version information about xml-xerces.  
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichXerces.java 226032 2003-01-10 21:29:08Z curcuru $
 */
public class WhichXerces implements WhichProject
{

    /** Our project name. */
    public static final String SERVICE_NAME = "Xerces";

    /** The Xerces-J implementation jar. */
    private static final String XERCES_JARNAME = "xerces.jar";

    /** The new Xerces-J implementation jar. */
    private static final String XERCESIMPL_JARNAME = "xercesImpl.jar";

    /** The Xerces-J 2.x xmlParserAPIs jar. */
    private static final String PARSERAPIS_JARNAME = "xmlParserAPIs.jar";

    /** The Xerces-J 1.x version class. */
    private static final String XERCES1_VERSION_CLASS =
        "org.webpki.android.org.apache.xerces.framework.Version";

    /** The Xerces-J 1.x version field. */
    private static final String XERCES1_VERSION_FIELD = "fVersion";

    /** The Xerces-J 2.x version class. */
    private static final String XERCES2_VERSION_CLASS =
        "org.webpki.android.org.apache.xerces.impl.Version";

    /** The Xerces-J 2.x version field. */
    private static final String XERCES2_VERSION_FIELD = "fVersion";

    /**
     * Gets version information for Xerces-J 1.x and 2.x,
     * and looks for xerces.jar and xmlParserAPIs.jar.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getInfo(Hashtable hash, String options)
    {

        if (null == hash)
            hash = new Hashtable();

        int xerces1found = WhichConstant.ITEM_UNKNOWN;
        int xerces2found = WhichConstant.ITEM_UNKNOWN;

        // Look for Xerces-J 1.x
        try
        {
            Class clazz = WhichClass.findClass(XERCES1_VERSION_CLASS,
                                               options);

            // Found Xerces-J 1.x, grab it's version field
            Field f = clazz.getField(XERCES1_VERSION_FIELD);
            String buf = (String) f.get(null);

            hash.put(SERVICE_NAME + "1" + WhichConstant.TAG_VERSION, buf);

            xerces1found = WhichConstant.ITEM_OK;
        }
        catch (Exception e1)
        {
            hash.put(SERVICE_NAME + "1" + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);

            xerces1found = WhichConstant.ITEM_NOTFOUND;
        }

        // Look for Xerces-J 2.x
        try
        {
            Class clazz = WhichClass.findClass(XERCES2_VERSION_CLASS,
                                               options);

            // Found Xerces-J 1.x, grab it's version field
            Field f = clazz.getField(XERCES2_VERSION_FIELD);
            String buf = (String) f.get(null);

            hash.put(SERVICE_NAME + "2" + WhichConstant.TAG_VERSION, buf);

            xerces2found = WhichConstant.ITEM_OK;
        }
        catch (Exception e1)
        {
            hash.put(SERVICE_NAME + "2" + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);

            xerces2found = WhichConstant.ITEM_NOTFOUND;
        }

        // Try to find EITHER xerces.jar OR xercesImpl.jar in 
        //  the classpath - take the min() of these, since 
        //  if we find either one it should be OK
        int jarRetVal = WhichJar.searchClasspaths(hash, XERCES_JARNAME,
                                                  options);
        jarRetVal = Math.min(jarRetVal, WhichJar.searchClasspaths(
                hash, XERCESIMPL_JARNAME, options));

        int ignoreThisReturnValue = WhichJar.searchClasspaths(hash,
                                        PARSERAPIS_JARNAME, options);

        // Report OK if either version of xerces was found
        int anyXercesFound = Math.min(xerces1found, xerces2found);
                                        
        return Math.max(jarRetVal, anyXercesFound);
    }
}
