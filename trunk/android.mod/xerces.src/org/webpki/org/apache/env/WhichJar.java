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

import java.io.File;
import java.io.InputStream;

import java.lang.reflect.Method;

import java.util.Hashtable;
import java.util.Properties;
import java.util.StringTokenizer;

/**
 * Static worker methods to find version info about jars and classpaths.  
 * 
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichJar.java 225992 2002-08-06 21:37:15Z curcuru $
 */
public abstract class WhichJar  // prevent instantiation; provide static services only
{

    /**
     * Generic worker method to print out java.class.path, 
     * sun.boot.class.path, and java.ext.dirs.
     *
     * @param hash to put information in
     * @param options to apply like strict or verbose
     */
    public static void getClasspathInfo(Hashtable hash, String options)
    {
        logProperty(hash, "java.class.path");
        logProperty(hash, "sun.boot.class.path");
        logProperty(hash, "java.ext.dirs");
    }

    /**
     * Worker method to print System.getProperty without 
     * putting nulls and catching exceptions.
     *
     * @param hash to put information in
     * @param propName to log
     */
    private static void logProperty(Hashtable hash, String propertyName)
    {
        try
        {
            hash.put(propertyName, System.getProperty(propertyName));
        } 
        catch (Throwable t)
        {
            /* no-op: ignore */
        }
    }

    /** SERVICE_NAME.  */
    public static final String SERVICE_NAME = "WhichJar";

    /**
     * Search all applicable classpath-like items for the named jar.  
     * Looks in each classpath (and bootclasspath, and ext dirs) 
     * for the jar and reports info about it.  
     *
     * @param hash to put information in
     * @param jarName to look for
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int searchClasspaths(Hashtable hash, String jarName,
                                       String options)
    {

        int retVal1 = searchPath(hash, "java.class.path", jarName, options);
        int retVal2 = searchPath(hash, "sun.boot.class.path", jarName,
                                 options);
        int retVal3 = searchDirs(hash, "java.ext.dirs", jarName, options);

        // Only return error info if options are strict
        if (WhichConstant.isStrict(options))
        {
            return Math.max(retVal1, Math.max(retVal2, retVal3));
        }
        else
        {

            // Otherwise return generic OK status
            return WhichConstant.ITEM_OK;
        }
    }

    /**
     * Search a classpath path for the named jar.  
     *
     * @param hash to put information in
     * @param pathName to get from System.getProperty()
     * @param jarName to look for, <b>case-insensitive</b>
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int searchPath(Hashtable hash, String pathName,
                                 String jarName, String options)
    {

        // Grab the actual path from the System
        String path = System.getProperty(pathName);
        if (null == path)
        {
            // Protect cases where the path isn't found
            hash.put(
                jarName
                + WhichConstant.ITEM_DESC[WhichConstant.ITEM_WARNING],
                    "searchPath [" + pathName
                    + "] not found!");

            return (WhichConstant.isStrict(options)
                              ? WhichConstant.ITEM_WARNING
                              : WhichConstant.ITEM_NOTFOUND);
        }
        
        StringTokenizer st = new StringTokenizer(path, File.pathSeparator);
        int retVal = WhichConstant.ITEM_UNKNOWN;
        boolean jarFound = false;

        while (st.hasMoreTokens())
        {

            String jarURI = st.nextToken();

            // If a path entry contains our jarName, process it
            if (jarURI.indexOf(jarName) > -1)
            {
                File jarFile = new File(jarURI);

                // If the actual file exists, log info about it...
                if (jarFile.exists())
                {

                    // ...but if it's *already* been found, log that too
                    if (jarFound)
                    {
                        Hashtable h = new Hashtable();
                        int multipleStatus = WhichConstant.isStrict(options)
                                             ? WhichConstant.ITEM_ERROR
                                             : WhichConstant.ITEM_UNKNOWN;

                        h.put(jarName
                              + WhichConstant.ITEM_DESC[multipleStatus], "jar on classpath multiple times!");

                        retVal = Math.max(retVal,
                                          getInfo(h, jarFile, options));
                        retVal = Math.max(retVal, multipleStatus);

                        hash.put(pathName + "." + jarName
                                 + WhichConstant.TAG_HASHINFO, h);

                        //@todo ERROR CASE: if found more than twice, we will overwrite this existing hash entries here - add a postfix?
                    }
                    else
                    {
                        retVal = Math.max(retVal,
                                          getInfo(hash, jarFile, options));
                        jarFound = true;
                    }
                }

                // ...if not, log it as missing
                else
                {
                    hash.put(
                        jarName
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_WARNING],
                            "classpath entry [" + jarURI
                            + "] does not exist on disk!");

                    retVal = Math.max(retVal,
                                      WhichConstant.isStrict(options)
                                      ? WhichConstant.ITEM_WARNING
                                      : WhichConstant.ITEM_NOTFOUND);
                }
            }  // end of for
        }  // end of while

        return retVal;
    }

    /**
     * Search a list of paths for the named jar.  
     *
     * @param hash to put information in
     * @param pathName to get from System.getProperty()
     * @param jarName to look for, <b>case-insensitive</b>
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int searchDirs(Hashtable hash, String pathName,
                                 String jarName, String options)
    {

        // Grab the actual path(s) from the System
        String path = System.getProperty(pathName);
        if (null == path)
        {
            // Protect cases where the path isn't found
            hash.put(
                jarName
                + WhichConstant.ITEM_DESC[WhichConstant.ITEM_WARNING],
                    " searchDirs [" + pathName
                    + "] not found!");

            return (WhichConstant.isStrict(options)
                              ? WhichConstant.ITEM_WARNING
                              : WhichConstant.ITEM_NOTFOUND);
        }

        StringTokenizer st = new StringTokenizer(path, File.pathSeparator);
        int retVal = WhichConstant.ITEM_UNKNOWN;

        // Search each dir and compile status
        while (st.hasMoreTokens())
        {
            String dir = st.nextToken();

            retVal = Math.max(retVal, searchDir(hash, dir, jarName, options));
        }

        return retVal;
    }

    /**
     * Search a single directory for the named jar.  
     *
     * @param hash to put information in
     * @param dir name of directory
     * @param jarName to look for, <b>case-insensitive</b>
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int searchDir(Hashtable hash, String dir, String jarName,
                                String options)
    {

        // Ensure the directory exists
        File searchDir = new File(dir);

        if (!searchDir.exists())
        {
            int retVal = WhichConstant.isStrict(options)
                         ? WhichConstant.ITEM_ERROR
                         : WhichConstant.ITEM_UNKNOWN;

            hash.put(SERVICE_NAME + "searchDir"
                     + WhichConstant.ITEM_DESC[retVal],
                     "searchDir does not exist: " + dir);

            return retVal;
        }

        // Find the jar file if it exists there
        File jarFile = new File(searchDir, jarName);

        return getInfo(hash, jarFile, options);
    }

    /**
     * Get version information about a specific .jar file.  
     * Current implementation simply checks the file size in bytes 
     * of the .jar file and does a lookup in WhichJar.properties 
     * to get a description of officially shipped .jars.
     * //@todo future versions should also lookup manifest 
     * version info from .jar files (but remember to provide 
     * fallbacks since we must also run on JDK 1.1.8!).
     *
     * @param hash to put information in
     * @param jarName of the .jar file
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int getInfo(Hashtable hash, File jarFile, String options)
    {

        // Check various error conditions first
        if (null == hash)
        {
            hash = new Hashtable();
        }

        if (null == jarFile)
        {
            hash.put(
                SERVICE_NAME
                + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR], "getInfo() called on null jarFile");

            return WhichConstant.ITEM_ERROR;
        }

        // Simplistic implementation: simply look up info about the 
        //  size of the actual .jar file in our tables
        // Note: may be replaced in the future to actually look up 
        //  info in the .jar's manifest file as well
        //@todo should use URLConnection or something to 
        //  be able to do http: etc.
        String jarName = jarFile.getName();

        if (jarFile.exists())
        {
            try
            {
                hash.put(jarName + WhichConstant.TAG_PATH,
                         jarFile.getAbsolutePath());

                String tmpInfo = getJarInfo(jarName, jarFile.length());

                if (null == tmpInfo)
                {
                    hash.put(jarName
                             + WhichConstant.ITEM_DESC[WhichConstant.ITEM_OK],
                                 "not from an official release, size:"
                                 + jarFile.length());

                    return WhichConstant.ITEM_OK;
                }
                else
                {
                    hash.put(
                        jarName
                        + WhichConstant.ITEM_DESC[WhichConstant.ITEM_SHIPPED], tmpInfo);

                    return WhichConstant.ITEM_SHIPPED;
                }
            }
            catch (Exception e)
            {
                hash.put(jarName
                         + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR],
                             jarFile.getAbsolutePath() + " threw: "
                             + e.toString());

                return WhichConstant.ITEM_ERROR;
            }
        }
        else  // of if(jarFile.exists())
        {
            int retVal = WhichConstant.isStrict(options)
                         ? WhichConstant.ITEM_ERROR
                         : WhichConstant.ITEM_UNKNOWN;

            hash.put(jarName + WhichConstant.ITEM_DESC[retVal],
                     jarFile.getAbsolutePath() + " does not exist");

            return retVal;
        }
    }

    /**
     * Get version information about a specific .jar file.  
     * Lookup the size/jarname pair in WhichJar.properties.
     *
     * @param hash to put information in
     * @param jarName of the .jar file
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    private static String getJarInfo(String jarName, long jarSize)
    {

        if (null == jarSizeTable)
            return null;

        final String SIZE_SEPARATOR = ".";

        return jarSizeTable.getProperty(String.valueOf(jarSize)
                                        + SIZE_SEPARATOR + jarName);
    }

    /**
     * Grab the bare filename off a path or URI.  
     *
     * @param URI original URI or path
     * @return just the bare filename after last separator
     */
    private static String getFilename(String URI)
    {

        if (null == URI)
            return null;

        final String URL_SEPARATOR = "/";

        return URI.substring(URI.lastIndexOf(URL_SEPARATOR));
    }

    /** 'org/apache/env/WhichJar.properties'.  */
    private static final String WHICHJAR_PROPS =
        "org/apache/env/WhichJar.properties";

    /** A Properties block of known officially shipped .jar names/sizes.  */
    protected static Properties jarSizeTable = new Properties();  // must be initialized

    static  // static initializer for the class
    {

        // Load each of the lists of .jar files
        loadJarTable(jarSizeTable, WHICHJAR_PROPS);
    }
    ;

    /**
     * Loads our jarSizeTable from WHICHJAR_PROPS.  
     *
     * @param table Properties block to load
     * @param tableURL name of .properties file to load
     */
    private static void loadJarTable(Properties table, String tableURL)
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

    /**
     * Get our file version info.  
     * @return String of our file version
     */
    public static String getVersion()
    {
        return "WhichJar.java:($Revision: 225992 $)";
    }
}
