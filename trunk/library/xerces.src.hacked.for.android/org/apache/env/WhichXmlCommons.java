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

import java.util.Hashtable;

/**
 * Get Version information about xml-commons code.  
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichXmlCommons.java 226032 2003-01-10 21:29:08Z curcuru $
 */
public class WhichXmlCommons implements WhichProject
{

    /** Our project name. */
    public static final String SERVICE_NAME = "XmlCommons";

    /** The xml-commons external standards jar. */
    private static final String XMLCOMMONS_JARNAME = "xml-apis.jar";

    /** The xml-commons external standards version class. */
    private static final String XMLCOMMONS_VERSION_CLASS =
        "org.apache.xmlcommons.Version";

    /** The xml-commons external standards version method. */
    private static final String XMLCOMMONS_VERSION_METHOD = "getVersion";  // String getVersion()

    /**
     * Gets information on external standards code in xml-commons 
     * project; finds the xml-commons version as well as the 
     * approximate versions of JAXP, DOM and SAX.  Looks for the 
     * default xml-apis.jar with external standards code.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getInfo(Hashtable hash, String options)
    {

        if (null == hash)
            hash = new Hashtable();

        // Get info about xml-commons project itself, including xml-apis.jar
        int status = getXmlCommonsInfo(hash, options);

        // Just determine JAXP version present...
        status = Math.max(status, getJAXPInfo(hash, options));

        // Just determine SAX version present...
        status = Math.max(status, getSAXInfo(hash, options));

        // Just determine DOM version present...
        status = Math.max(status, getDOMInfo(hash, options));

        return status;
    }

    /**
     * Calls xmlcommons.Version.getVersion and looks for xml-apis.jar.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getXmlCommonsInfo(Hashtable hash, String options)
    {

        int status = WhichConstant.ITEM_UNKNOWN;

        try
        {
            final Class noArgs[] = new Class[0];
            Class clazz = WhichClass.findClass(XMLCOMMONS_VERSION_CLASS,
                                               options);
            Method method = clazz.getMethod(XMLCOMMONS_VERSION_METHOD,
                                            noArgs);
            Object returnValue = method.invoke(null, new Object[0]);

            hash.put(SERVICE_NAME + WhichConstant.TAG_VERSION,
                     (String) returnValue);

            status = WhichConstant.ITEM_OK;
        }
        catch (Exception e)
        {
            hash.put(SERVICE_NAME + WhichConstant.TAG_VERSION,
                     WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]);

            status = WhichConstant.ITEM_NOTFOUND;
        }

        // Try to find appropriate jar in the classpath, etc.
        int jarStatus = WhichJar.searchClasspaths(hash, XMLCOMMONS_JARNAME,
                                                  options);

        return Math.max(jarStatus, status);
    }

    /**
     * Gets JAXP version info and looks for jaxp.jar.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getJAXPInfo(Hashtable hash, String options)
    {

        final String INFONAME = SERVICE_NAME + ".jaxp";
        int status = WhichConstant.ITEM_UNKNOWN;
        Class jaxpClazz = null;

        try
        {
            final Class noArgs[] = new Class[0];

            jaxpClazz =
                WhichClass.findClass("javax.xml.parsers.DocumentBuilder",
                                     options);

            Method method = jaxpClazz.getMethod("getDOMImplementation",
                                                noArgs);

            // If we succeeded, we at least have JAXP 1.1 available
            hash.put(INFONAME + WhichConstant.TAG_VERSION, "1.1");

            status = WhichConstant.ITEM_SHIPPED;
        }
        catch (Exception e)
        {
            if (null != jaxpClazz)
            {

                // We must have found the class itself, just not the 
                //  method, so we (probably) have JAXP 1.0.1
                hash.put(INFONAME + WhichConstant.TAG_VERSION,
                         "apparently-JAXP-1.0.1"
                         + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                status = WhichConstant.ITEM_ERROR;
            }
            else
            {

                // We couldn't even find the class, and don't have 
                //  any JAXP support at all, or only have the 
                //  transform half of it
                hash.put(INFONAME + WhichConstant.TAG_VERSION,
                         "JAXP-nowhere"
                         + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                status = WhichConstant.ITEM_ERROR;
            }
        }

        // Try to find older jaxp.jar in the classpath, etc.
        int ignored = WhichJar.searchClasspaths(hash, "jaxp.jar", options);
        
        // Also try to find varous Sun shipped classes from JAXP packs, etc.
        ignored = WhichJar.searchClasspaths(hash, "dom.jar", options);
        ignored = WhichJar.searchClasspaths(hash, "sax.jar", options);
        ignored = WhichJar.searchClasspaths(hash, "jaxp-api.jar", options);
        

        return status;
    }

    /**
     * Gets SAX version info and looks for sax.jar.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getSAXInfo(Hashtable hash, String options)
    {

        final String INFONAME = SERVICE_NAME + ".sax";
        int status = WhichConstant.ITEM_UNKNOWN;
        Class saxClazz = null;
        final String SAX_VERSION1_CLASS = "org.xml.sax.Parser";
        final String SAX_VERSION1_METHOD = "parse";  // String
        final String SAX_VERSION2BETA_CLASS = "org.xml.sax.XMLReader";
        final String SAX_VERSION2BETA_METHOD = "parse";  // String
        final String SAX_VERSION2_CLASS =
            "org.xml.sax.helpers.AttributesImpl";
        final String SAX_VERSION2_METHOD = "setAttributes";  // Attributes
        final Class oneStringArg[] = { java.lang.String.class };

        try
        {
            final Class attributesArg[] = {
                WhichClass.findClass("org.xml.sax.Attributes", options) };

            saxClazz = WhichClass.findClass(SAX_VERSION2_CLASS, options);

            Method method = saxClazz.getMethod(SAX_VERSION2_METHOD,
                                               attributesArg);

            // If we succeeded, we at least have SAX 2.0 final available
            hash.put(INFONAME + WhichConstant.TAG_VERSION, "2.0");

            status = WhichConstant.ITEM_SHIPPED;
        }
        catch (Exception e)
        {
            try
            {
                saxClazz = WhichClass.findClass(SAX_VERSION2BETA_CLASS,
                                                options);

                Method method = saxClazz.getMethod(SAX_VERSION2BETA_METHOD,
                                                   oneStringArg);

                // If we succeeded, we have SAX 2.0 beta2 available, 
                //  which isn't recommended but should be OK
                hash.put(
                    INFONAME + WhichConstant.TAG_VERSION,
                    "2.0beta2"
                    + WhichConstant.ITEM_DESC[WhichConstant.ITEM_WARNING]);

                status = WhichConstant.ITEM_OK;
            }
            catch (Exception e2)
            {
                try
                {
                    saxClazz = WhichClass.findClass(SAX_VERSION1_CLASS,
                                                    options);

                    Method method = saxClazz.getMethod(SAX_VERSION1_METHOD,
                                                       oneStringArg);

                    // If we succeeded, we have SAX 1.0 available, 
                    //  which probably will not work
                    hash.put(
                        INFONAME + WhichConstant.TAG_VERSION,
                        "1.x"
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                    status = WhichConstant.ITEM_ERROR;
                }
                catch (Exception e3)
                {

                    // No SAX classes available anywhere
                    hash.put(
                        INFONAME + WhichConstant.TAG_VERSION,
                        WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                    status = WhichConstant.ITEM_ERROR;
                }
            }
        }

        // Try to find older sax.jar in the classpath, etc.
        int ignored = WhichJar.searchClasspaths(hash, "sax.jar", options);

        return status;
    }

    /**
     * Gets DOM version info and looks for dom.jar.  
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public int getDOMInfo(Hashtable hash, String options)
    {

        final String INFONAME = SERVICE_NAME + ".dom";
        int status = WhichConstant.ITEM_UNKNOWN;
        Class domClazz = null;
        final String DOM_LEVEL2_CLASS = "org.w3c.dom.Document";
        final String DOM_LEVEL2_METHOD = "createElementNS";  // String, String
        final String DOM_LEVEL2WD_CLASS = "org.w3c.dom.Node";
        final String DOM_LEVEL2WD_METHOD = "supported";  // String, String
        final String DOM_LEVEL2FD_CLASS = "org.w3c.dom.Node";
        final String DOM_LEVEL2FD_METHOD = "isSupported";  // String, String
        final Class twoStringArgs[] = { java.lang.String.class,
                                        java.lang.String.class };

        try
        {
            domClazz = WhichClass.findClass(DOM_LEVEL2_CLASS, options);

            Method method = domClazz.getMethod(DOM_LEVEL2_METHOD,
                                               twoStringArgs);

            // If we succeeded, we have loaded interfaces from a 
            //  level 2 DOM somewhere
            hash.put(INFONAME + WhichConstant.TAG_VERSION, "2.0");

            status = WhichConstant.ITEM_SHIPPED;
        }
        catch (Exception e)
        {
            try
            {

                // Check for the working draft version, which is 
                //  commonly found, but won't work anymore
                domClazz = WhichClass.findClass(DOM_LEVEL2WD_CLASS, options);

                Method method = domClazz.getMethod(DOM_LEVEL2WD_METHOD,
                                                   twoStringArgs);

                // If we succeeded, we have loaded interfaces from a 
                //  level 2 DOM somewhere
                hash.put(INFONAME + WhichConstant.TAG_VERSION,
                         "2.0wd"
                         + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                status = WhichConstant.ITEM_ERROR;
            }
            catch (Exception e2)
            {
                try
                {

                    // Check for the final draft version, which also 
                    //  won't work anymore
                    domClazz = WhichClass.findClass(DOM_LEVEL2FD_CLASS,
                                                    options);

                    Method method = domClazz.getMethod(DOM_LEVEL2FD_METHOD,
                                                       twoStringArgs);

                    // If we succeeded, we have loaded interfaces from a 
                    //  level 2 DOM somewhere
                    hash.put(
                        INFONAME + WhichConstant.TAG_VERSION,
                        "2.0fd"
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                    status = WhichConstant.ITEM_ERROR;
                }
                catch (Exception e3)
                {

                    // No DOM classes available anywhere
                    hash.put(
                        INFONAME + WhichConstant.TAG_VERSION,
                        WhichConstant.ITEM_DESC[WhichConstant.ITEM_NOTFOUND]
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR]);

                    status = WhichConstant.ITEM_ERROR;
                }
            }
        }

        //@todo load an actual DOM implmementation and query it as well
        //@todo load an actual DOM implmementation and check if 
        //  isNamespaceAware() == true, which is needed to parse 
        //  xsl stylesheet files into a DOM
        // Try to find older dom.jar in the classpath, etc.
        int ignored = WhichJar.searchClasspaths(hash, "dom.jar", options);

        return status;
    }
}
