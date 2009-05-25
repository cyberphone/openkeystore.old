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
package org.apache.env;

import java.lang.reflect.Method;
import java.lang.reflect.Field;

import java.util.Hashtable;

/**
 * Get Version information about xml-xalan.  
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichXalan.java 225939 2001-12-11 17:42:50Z curcuru $
 */
public class WhichXalan implements WhichProject
{

    /** Our project name. */
    public static final String SERVICE_NAME = "Xalan";

    /** The Xalan-J implementation jar. */
    private static final String XALAN_JARNAME = "xalan.jar";

    /** The Xalan-J xml-apis jar. */
    private static final String XMLAPIS_JARNAME = "xml-apis.jar";

    /** The Xalan-J 1.x version class. */
    private static final String XALAN1_VERSION_CLASS =
        "org.apache.xalan.xslt.XSLProcessorVersion";

    /** The Xalan-J 2.0, 2.1 version class. */
    private static final String XALAN2_VERSION_CLASS =
        "org.apache.xalan.processor.XSLProcessorVersion";

    /** The Xalan-J 2.2+ version class. */
    private static final String XALAN2_2_VERSION_CLASS =
        "org.apache.xalan.Version";

    /** The Xalan-J 2.2+ version method. */
    private static final String XALAN2_2_VERSION_METHOD = "getVersion";

    /**
     * Finds version information from Xalan-J 1.x, 2.x, 2.2+, and 
     * looks for xalan.jar and xml-apis.jar.  Only looks for 1.x 
     * classes for information; does not report status on them.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getInfo(Hashtable hash, String options)
    {

        if (null == hash)
            hash = new Hashtable();

        // Try to find Xalan-specific classes
        try
        {

            // Attempt to find Xalan-J 1.x only as a historical 
            //  note; do not report on success/failure of this
            Class clazz = WhichClass.findClass(XALAN1_VERSION_CLASS, options);

            // Found Xalan-J 1.x, grab it's version fields
            StringBuffer buf = new StringBuffer();
            Field f = clazz.getField("PRODUCT");

            buf.append(f.get(null));
            buf.append(';');

            f = clazz.getField("LANGUAGE");

            buf.append(f.get(null));
            buf.append(';');

            f = clazz.getField("S_VERSION");

            buf.append(f.get(null));
            buf.append(';');
            hash.put(SERVICE_NAME + "1" + WhichConstant.TAG_VERSION,
                     buf.toString());
        }
        catch (Exception e1)
        {
            hash.put(SERVICE_NAME + "1" + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);
        }

        int xalan2found = WhichConstant.ITEM_UNKNOWN;
        int xalan22found = WhichConstant.ITEM_UNKNOWN;

        try
        {

            // NOTE: This is the old Xalan 2.0, 2.1, 2.2 version class, 
            Class clazz = WhichClass.findClass(XALAN2_VERSION_CLASS, options);

            // Found Xalan-J 2.x, grab it's version fields
            StringBuffer buf = new StringBuffer();
            Field f = clazz.getField("S_VERSION");

            buf.append(f.get(null));
            hash.put(SERVICE_NAME + "2x" + WhichConstant.TAG_VERSION,
                     buf.toString());

            xalan2found = WhichConstant.ITEM_OK;
        }
        catch (Exception e2)
        {
            hash.put(SERVICE_NAME + "2x" + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);

            xalan2found = WhichConstant.ITEM_NOTFOUND;
        }

        try
        {

            // NOTE: This is the new Xalan 2.2 and up version class, 
            final Class noArgs[] = new Class[0];
            Class clazz = WhichClass.findClass(XALAN2_2_VERSION_CLASS,
                                               options);
            Method method = clazz.getMethod(XALAN2_2_VERSION_METHOD, noArgs);
            Object returnValue = method.invoke(null, new Object[0]);

            hash.put(SERVICE_NAME + "22+" + WhichConstant.TAG_VERSION,
                     (String) returnValue);

            xalan22found = WhichConstant.ITEM_OK;
        }
        catch (Exception e3)
        {
            hash.put(SERVICE_NAME + "22+" + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);

            xalan22found = WhichConstant.ITEM_NOTFOUND;
        }

        // Try to find xalan.jar in the classpath, etc.
        int jarRetVal = WhichJar.searchClasspaths(hash, XALAN_JARNAME,
                                                  options);
        int ignoreThisReturnValue = WhichJar.searchClasspaths(hash,
                                        XMLAPIS_JARNAME, options);

        return Math.max(jarRetVal, Math.max(xalan2found, xalan22found));
    }
}
