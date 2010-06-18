/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.io.IOException;

public enum APIDescriptors
  {
    SET_CERTIFICATE_PATH            ("setCertificatePath"),
    SET_SYMMETRIC_KEY               ("setSymmetricKey"),
    RESTORE_PRIVATE_KEY             ("restorePrivateKey"),
    CLOSE_PROVISIONING_SESSION      ("closeProvisioningSession"),
    PP_DELETE_KEY                   ("pp_deleteKey"),
    PP_UPDATE_KEY                   ("pp_updateKey"),
    PP_CLONE_KEY_PROTECTION         ("pp_cloneKeyProtection"),
    CREATE_KEY_PAIR                 ("createKeyPair"),
    CREATE_PIN_POLICY               ("createPINPolicy"),
    CREATE_PUK_POLICY               ("createPUKPolicy"),
    ADD_EXTENSION                   ("addExtension");

    private byte[] binary;       // As expressed in MACs

    private APIDescriptors (String string)
      {
        try
          {
            binary = string.getBytes ("UTF-8");
          }
        catch (IOException e)
          {
            binary = null;
          }
      }
    
    public byte[] getBinary ()
      {
        return binary;
      }

  }
