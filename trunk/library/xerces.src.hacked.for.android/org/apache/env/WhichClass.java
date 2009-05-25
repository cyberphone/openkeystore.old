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

/**
 * Class finding service.  
 * 
 * <p>This effectively replaces all Class.forName() calls in this 
 * package.  Similar to code in javax.xml.*.FactoryFinder.  
 * Options included for future use; they could specify something 
 * like LOCAL_CLASSLOADER_ONLY for servlet environments, etc.</p>
 *
 * <p>This class detects JDKs 1.1.x versus 1.2+ and may attempt to 
 * either use the current classLoader or may use a contextClassLoader.  
 * Note that in some servlet environments or in IDE environments 
 * like <a href="http://www.eclipse.org">Eclipse</a> that the 
 * difference between classloaders is very important!  Changes in 
 * the JAXP FactoryFinder classes should be actively evaluated for 
 * inclusion/copying here.</p>
 * 
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichClass.java 226032 2003-01-10 21:29:08Z curcuru $
 */
public abstract class WhichClass  // Prevent instantiation; only provide static services
{

    /**
     * Worker method to load a class.
     * Factor out loading classes for future use and JDK differences.
     * Similar to javax.xml.*.FactoryFinder
     * 
     * @param className name of class to load from
     * an appropriate classLoader
     * @param options currently unused
     * @return the class asked for
     *
     * @throws ClassNotFoundException
     */
    public static Class findClass(String className, String options)
            throws ClassNotFoundException
    {

        ClassLoader classLoader = WhichClass.findClassLoader(options);

        if (classLoader == null)
        {
            return Class.forName(className);
        }
        else
        {
            return classLoader.loadClass(className);
        }
    }

    /**
     * Worker method to figure out which ClassLoader to use.
     * For JDK 1.2 and later use the context ClassLoader.
     * Similar to javax.xml.*.FactoryFinder
     *
     * @param options currently unused
     * @return the appropriate ClassLoader
     *
     * @throws ClassNotFoundException
     */
    protected static ClassLoader findClassLoader(String options)
            throws ClassNotFoundException
    {

        ClassLoader classLoader = null;
        Method m = null;

        try
        {
            m = Thread.class.getMethod("getContextClassLoader", null);
        }
        catch (NoSuchMethodException nsme)
        {

            // Assume that we are running JDK 1.1, use the current ClassLoader
            // Note that this will be the classloader from 
            //  which.jar's loading, not necessarily the one from 
            //  an external caller's perspective (I think)
            return WhichClass.class.getClassLoader();
        }

        try
        {
            return (ClassLoader) m.invoke(Thread.currentThread(), null);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}
