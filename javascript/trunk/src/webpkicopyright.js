/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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

////////////////////////////////////////////////////////////////////////////////////////////
// This file contains a JSON encoder/decoder written in JavaScript (ECMA V5) supporting:  //
// - JCS (JSON Cleartext Signature):                                                      //
//   https://openkeystore.googlecode.com/svn/resources/trunk/docs/jcs.html                //
// - JSON object validation and automatic instantiation                                   //
//                                                                                        //
// The parser is essentially a JavaScript copy of a Java-based version available at:      //
// https://code.google.com/p/openkeystore/source/browse/library/trunk/src/org/webpki/json //
//                                                                                        //
// Note: The cryptographic operations are supposed to be performed by WebCrypto when      //
// used in a browser application.                                                         //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////
