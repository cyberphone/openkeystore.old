/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 2001-2002 The Apache Software Foundation.  
 * All rights reserved.
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

import java.io.PrintWriter;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * General environment checking and version finding service; 
 * main external entrypoints and command line interface.  
 * 
 * <p>Which is the command line interface to the org.apache.env 
 * package.  Simply put, it provides a simplistic 
 * check of a user's actual environment for debugging and 
 * product support purposes by detecting the specific versions 
 * of commonly installed classes in the environment.</p>
 *
 * <p>Which and related service classes provide a framework for 
 * looking for version information and passing it around in 
 * hashtables.  Users can plug in their own implementations of 
 * WhichProject classes to get custom version info about any 
 * product.</p>
 *
 * <p>One important usage note: you must call Which (or subclasses) 
 * <b>in the environment that you wish to check</b>.  I.e. if you 
 * have a problem with a command line tool, then call Which from 
 * the same command line environment.  If you have a problem with a 
 * servlet, you <b>must</b> call Which.blah() from your servlet as 
 * it's installed in an actual container.</p>
 *
 * <p><b>Usage</b> - command line:<br/>  
 * <code>
 * java org.apache.env.Which [project;WhichProject] [-options]
 * </code></p>
 * 
 * <p><b>Usage</b> - from program:<br/>  
 * <code>
 * int status = org.apache.env.Which.which(hash, projects, options);
 * </code></p>
 *
 * <p><b>Usage</b> - from XSLT stylesheet in <a href="http://xml.apache.org/xalan-j/">Xalan-J</a>:<br/>
 * (add which.jar to your classpath and run the following stylesheet)
 * <pre>
 * &lt;?xml version="1.0"?>
 * &lt;xsl:stylesheet version="1.0"
 *     xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
 *     xmlns:xalan="http://xml.apache.org/xalan"
 *     exclude-result-prefixes="xalan">
 *     &lt;xsl:output indent="yes"/>
 *     &lt;xsl:template match="/">
 *       &lt;xsl:copy-of select="xalan:checkEnvironment()"/>
 *     &lt;/xsl:template>
 * &lt;/xsl:stylesheet>
 * </pre></p>
 * <p>Original credit to org.apache.xalan.xslt.EnvironmentCheck</p>
 * @author shane_curcuru@us.ibm.com
 * @version $Id: Which.java 226174 2004-10-18 16:21:45Z curcuru $
 */
public class Which
{

    /**
     * Command line runnability.  
     * @param args command line args
     */
    public static void main(String[] args)
    {
        // Create instance and have it run
        Which app = new Which();
        app.doMain(args);
    }

    /**
     * Instance worker method to handle main().  
     * @param args command line args
     */
    public void doMain(String[] args)
    {

        // Instance method to run from command line
        if (!parseArgs(args))
        {
            outWriter.println(usage());
            outWriter.println("Bad argument or help (?) asked for, aborting");
            return;
        }

        Hashtable hash = new Hashtable();        

        // Grab info on all projects...
        int status = which(hash, projectsBuf.toString(), optionsBuf.toString());

        // ...then report it to a writer
        reportProjectsInfo(hash, optionsBuf.toString(), status, outWriter);
    }

    /**
     * Which - get all info.  
     * Worker method called from doMain or suitable for calling 
     * from other programs.  
     *
     * @param hash to put information in
     * @param projects to get information about
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int which(Hashtable hash, String projects, String options)
    {
        if (null == hash)
            hash = new Hashtable();

        getGeneralInfo(hash, options);

        int status = getProjectsInfo(hash, projects, options);

        hash.put("Which" + WhichConstant.TAG_STATUS,
                 WhichConstant.ITEM_DESC[status]);

        return status;
    }

    /**
     * Grab a couple of generally useful items, like classpath, 
     * java version, version of this file, etc..  
     *
     * @param hash to put information in
     * @param projects to get information about
     */
    public static void getGeneralInfo(Hashtable hash, String options)
    {

        hash.put("Which" + WhichConstant.TAG_VERSION, getVersion());
        WhichJar.getClasspathInfo(hash, options);
        try
        {
            hash.put("java" + WhichConstant.TAG_VERSION, System.getProperty("java.version"));
            hash.put("file.encoding", System.getProperty("file.encoding"));
            hash.put("java.vendor", System.getProperty("java.vendor"));
            hash.put("os.name", System.getProperty("os.name"));
        } 
        catch (Exception e)
        {
            hash.put("Which" + WhichConstant.TAG_ERROR, "Accessing System.getProperty(...) threw: " + e.toString());
        }
        try
        {
            // Not available on JDK 1.1.x
            hash.put("java.runtime.name", System.getProperty("java.runtime.name"));
        } 
        catch (Exception e)
        {
            hash.put("Which" + WhichConstant.TAG_ERROR + "11x", "Accessing System.getProperty(java.runtime.name) threw: " + e.toString());
        
        }
    }

    /**
     * Get information from various project's WhichProject impls.  
     * 
     * <p>Each project's info is put into a subhash.  
     * Note: if projects is null, we use DEFAULT_PROJECTS.</p>
     *
     * @param hash to put information in
     * @param projects to get information about
     * @param options to apply like strict or verbose
     * @return status information from WhichConstant
     */
    public static int getProjectsInfo(Hashtable hash, String projects,
                               String options)
    {

        if (null == hash)
            hash = new Hashtable();

        if ((null == projects) || (projects.length() < 1))
        {
            projects = DEFAULT_PROJECTS;

            hash.put("Which.special-note",
                     "No -projects provided, using DEFAULT_PROJECTS");
        }

        // For each listed project, find it's whicher 
        //  and ask it to fill in hash
        int retVal = WhichConstant.ITEM_UNKNOWN;
        StringTokenizer st = new StringTokenizer(projects, SEPARATOR);

        while (st.hasMoreTokens())
        {
            String projName = st.nextToken();

            // Each project has it's info put in a subhashtable
            try
            {
                Hashtable subHash = new Hashtable();
                WhichProject proj = WhichFactory.newWhichProject(projName,
                                        options);
                int subStatus = proj.getInfo(subHash, options);
                
                subHash.put(projName + WhichConstant.TAG_STATUS,
                        WhichConstant.ITEM_DESC[subStatus]);

                hash.put(projName + WhichConstant.TAG_HASHINFO, subHash);

                retVal = Math.max(subStatus, retVal);
            }
            catch (Exception e)
            {

                // oops, couldn't get asked for project; report error
                hash.put(projName
                         + WhichConstant.ITEM_DESC[WhichConstant.ITEM_ERROR],
                             "newWhichProject threw: " + e.toString());
                e.printStackTrace();     

                retVal = Math.max(WhichConstant.ITEM_ERROR, retVal);
            }
        }

        return retVal;
    }

    /**
     * Print information from which() into the PrintWriter.  
     * 
     * <p>Simplistic implementation to report to a writer.</p>
     *
     * @param hash to get info from (may have subhashtables)
     * @param options to apply like strict or verbose
     * @param status from finding version info
     * @param out PrintWriter to send Properties.list()-like 
     * output to
     */
    public void reportProjectsInfo(Hashtable hash, String options,
                                   int status, PrintWriter out)
    {
        reportHashtable(hash, "Which report", out);
    }

    /**
     * Print information from a hashtable into the PrintWriter.  
     * 
     * <p>Provides a pre-order traversal where the parent hash 
     * has it's output dumped before recursing to any child 
     * sub hashes. Sorta looks like Properties.list() output.</p>
     *
     * @param hash to get info from (may have subhashtables)
     * @param name to print as header for this hash
     * @param out PrintWriter to send Properties.list()-like 
     * output to
     */
    protected void reportHashtable(Hashtable hash, String name,
                                   PrintWriter out)
    {

        out.println("#---- BEGIN: " + name);

        if (null == hash)
            return;

        Enumeration keysEnum = hash.keys();
        Vector v = new Vector();

        while (keysEnum.hasMoreElements())
        {
            Object key = keysEnum.nextElement();
            String keyStr = key.toString();
            Object item = hash.get(key);

            if (item instanceof Hashtable)
            {

                // Ensure a pre-order traversal
                v.addElement(keyStr);
                v.addElement((Hashtable) item);
            }
            else
            {
                out.println(keyStr + "=" + item);
            }
        }

        keysEnum = v.elements();

        while (keysEnum.hasMoreElements())
        {
            String n = (String) keysEnum.nextElement();
            Hashtable h = (Hashtable) keysEnum.nextElement();

            reportHashtable(h, n, out);
        }

        out.println("#----   END: " + name);
    }

    /**
     * Return our usage statement.  
     * @return String of our usage
     */
    protected String usage()
    {
        return "Which: find classes and jars in your environment\n"
             + "usage: java org.apache.env.Which [-options] [project;org.MyWhichProject]\n";
    }

    /**
     * Parse commandline args, return false if help asked for.  
     *
     * @param args array of commandline args
     * @return true if OK, false if error/usage/help needed
     */
    protected boolean parseArgs(String[] args)
    {

        final String OPTION_PREFIX = "-";
        final String OPTION_HELP = "?";

        // Parse args into instance vars, return false if fatal error
        int numArgs = args.length;

        for (int k = 0; k < numArgs; k++)
        {

            // if any arg asks for help return false
            if (args[k].indexOf(OPTION_HELP) > -1)
            {
                return false;
            }

            // if any arg starts with -, add to optionsBuf
            if (args[k].startsWith(OPTION_PREFIX))
            {
                optionsBuf.append(args[k]);
                optionsBuf.append(SEPARATOR);
            }

            // else it's a project, add to projects
            else
            {
                projectsBuf.append(args[k]);
                projectsBuf.append(SEPARATOR);
            }
        }

        return true;
    }

    /**
     * Get simple version info about org.apache.env.Which and 
     * related classes.  
     * @return String of our file version
     */
    public static String getVersion()
    {
        return "Which.java:($Revision: 226174 $) " + WhichJar.getVersion();
    }

    /** Generic ';' separator for various items. */
    public static final String SEPARATOR = ";";

    /** Default set of projects to use if none provided. */
    public static final String DEFAULT_PROJECTS =
        "XmlCommons;Xerces;Xalan;Crimson;Ant";

    /** optionsBuf.  */
    protected StringBuffer optionsBuf = new StringBuffer();  // various internal options

    /** projectsBuf.  */
    protected StringBuffer projectsBuf = new StringBuffer();  // various projects we're asked to 'which'

    /** outWriter.  */
    protected PrintWriter outWriter = new PrintWriter(System.out, true);  // where we send output
}
