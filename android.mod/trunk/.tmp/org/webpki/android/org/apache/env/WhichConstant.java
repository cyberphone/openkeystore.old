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

/**
 * Simple static constants used throughout org.webpki.android.org.apache.env package.  
 * 
 * @author shane_curcuru@us.ibm.com
 * @version $Id: WhichConstant.java 225939 2001-12-11 17:42:50Z curcuru $
 */
public abstract class WhichConstant
{

    /** Item is Unknown, or don't care.  */
    public static final int ITEM_UNKNOWN = 0;

    /** Item is Provably a shipped version.  */
    public static final int ITEM_SHIPPED = 1;

    /** Item is Version appears to be OK.  */
    public static final int ITEM_OK = 2; 

    /** Item is Item was not found, but might be ok.  */
    public static final int ITEM_NOTFOUND = 3;

    /** Item is Possible problem.  */
    public static final int ITEM_WARNING = 4;

    /** Item is Definite problem.  */
    public static final int ITEM_ERROR = 5;

    /** Descriptive strings for ITEM_ constants; keep in sync.  */
    public static final String[] ITEM_DESC =
    {

        /* Keep in sync with above ITEM_* constants */
        ".unknown", 
        ".shipped-version", 
        ".ok-present", 
        ".not-found",
        ".warning", 
        ".error"
    };

    /** Tag denoting version info follows.  */
    public static final String TAG_VERSION = ".version";

    /** Tag denoting a generic error occoured.  */
    public static final String TAG_ERROR = ".error";

    /** Tag denoting a subhash of information is here.  */
    public static final String TAG_HASHINFO = ".hashinfo";

    /** Tag denoting the path to a file (.jar, etc.).  */
    public static final String TAG_PATH = ".path";

    /** Tag denoting the status of a WhichProject hash.  */
    public static final String TAG_STATUS = ".status";

    /** Strict option asks Whichers to return an error if 
      * required classes, etc. are not found.  */
    public static final String OPTION_STRICT = "strict";

    /** Verbose option asks Whichers to return extra info.  */
    public static final String OPTION_VERBOSE = "verbose";

    /**
     * Check if options include strict.  
     *
     * @param options from your method
     * @return true if OPTION_STRICT is present
     */
    public static boolean isStrict(String options)
    {

        if (null == options)
            return false;

        return (options.indexOf(OPTION_STRICT) > -1);
    }

    /**
     * Check if options include verbose.  
     *
     * @param options from your method
     * @return true if OPTION_VERBOSE is present
     */
    public static boolean isVerbose(String options)
    {

        if (null == options)
            return false;

        return (options.indexOf(OPTION_VERBOSE) > -1);
    }
}
