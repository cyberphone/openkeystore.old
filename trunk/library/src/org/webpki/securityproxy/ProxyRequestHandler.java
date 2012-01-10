/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.securityproxy;

/**
 * Security proxy client request handler interface.
 * 
 * Note that errors should be taken care of by the handler implementation
 * and for non-fatal situations return an error object to the actual caller.
 */
public interface ProxyRequestHandler
  {
    /**
     * @param proxy_req_wrapper the request
     * @return a suitable return to the external caller
     */
    public ProxyResponseWrapper handleProxyRequest (ProxyRequestWrapper proxy_req_wrapper);
  }
