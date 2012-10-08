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
package org.webpki.org.apache.env;

import java.io.InputStream;

import java.lang.reflect.Method;

import java.util.Properties;

/**
 * Simple factory class for WhichProject implementations.  
 * A list of 'installed' WhichProject impls is kept in our matching 
 * org/apache/env/WhichFactory.properties file.
 *
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichFactory.java 225939 2001-12-11 17:42:50Z curcuru $
 */
public abstract class WhichFactory  // prevent instantiation; provide static services only
{

    /** org.webpki.org.apache.env.Which, prepended to unknown projectnames.  */
    public static final String DEFAULT_WHICHCLASS = "org.webpki.org.apache.env.Which";

    /** 'WhichFactory'.  */
    public static final String SERVICE_NAME = "WhichFactory";

    /**
     * Factory method to get a WhichProject implementation for the name.  
     * <p>Returns a WhichProject using the name as an FQCN; or looks 
     * up the name in WhichFactory.properties; or assuming it's 
     * a simple name and appends DEFAULT_WHICHCLASS on the front.</p>
     *
     * @param name FQCN, simple name, or installed name of a 
     * WhichProject implementation class
     * @param options to use when getting the class
     * @return a WhichProject object
     *
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InstantiationException
     */
    public static WhichProject newWhichProject(String name, String options)
            throws ClassNotFoundException, InstantiationException,
                   IllegalAccessException  //@todo change to catch and return null instead?
    {

        Class clazz;

        try
        {

            // Assume it's a FQCN first...
            clazz = WhichClass.findClass(name, options);
        }
        catch (ClassNotFoundException cnfe)
        {
            try
            {

                // ...then try installedWhichers...
                String implName = installedWhichers.getProperty(name);

                // Note this is inefficient to simply let it throw
                //  cnfe2 if we get null back, but it does work
                if (null == implName)
                    throw new ClassNotFoundException();

                clazz = WhichClass.findClass(implName, options);
            }
            catch (ClassNotFoundException cnfe2)
            {

                // ...otherwise it's a shortname of just the project name
                clazz = WhichClass.findClass(DEFAULT_WHICHCLASS + name,
                                             options);
            }
        }

        if (null == clazz)
            throw new ClassNotFoundException(name);  //@todo add description

        return (WhichProject) clazz.newInstance();
    }

    /** org/apache/env/WhichFactory.properties.  */
    private static final String WHICHFACTORY_PROPS =
        "org/apache/env/WhichFactory.properties";

    /** List of 'installed' WhichProject implementations.  */
    protected static Properties installedWhichers = new Properties();  // must be initialized

    static  // static initializer for the class
    {

        // Load each of the lists of .jar files
        loadWhichInstall(installedWhichers, WHICHFACTORY_PROPS);
    }
    ;

    /**
     * Loads our installedWhichers from WHICHFACTORY_PROPS.  
     *
     * @param table Properties block to load
     * @param tableURL name of .properties file to load
     */
    private static void loadWhichInstall(Properties table, String tableURL)
    {

        if (null == table)
            table = new Properties();

        try
        {
            InputStream is = null;

            try
            {
                final Class[] NO_CLASSES = new Class[0];
                final Object[] NO_OBJS = new Object[0];
                Method getCCL =
                    Thread.class.getMethod("getContextClassLoader",
                                           NO_CLASSES);

                if (getCCL != null)
                {
                    ClassLoader contextClassLoader =
                        (ClassLoader) getCCL.invoke(Thread.currentThread(),
                                                    NO_OBJS);

                    is = contextClassLoader.getResourceAsStream(tableURL);
                }
            }
            catch (Exception e)
            { /*no-op */
            }

            if (null == is)
            {
                is = WhichJar.class.getResourceAsStream("/" + tableURL);
            }

            table.load(is);
            is.close();
        }
        catch (Exception e)
        {

            // Leave table as-is; presumably it's null
            System.err.println(SERVICE_NAME + " loadJarTable threw: "
                               + e.toString());
            e.printStackTrace();
        }
    }
}
