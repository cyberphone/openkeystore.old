/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

import java.util.Date;
import java.util.Vector;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.util.ISODateTime;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    public class KeyManagementKeyUpdateHolder {
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder>();

        PublicKey kmk;

        byte[] authorization;

        public KeyManagementKeyUpdateHolder[] KeyManagementKeyUpdateHolders() {
            return children.toArray(new KeyManagementKeyUpdateHolder[0]);
        }

        public PublicKey getKeyManagementKey() {
            return kmk;
        }

        KeyManagementKeyUpdateHolder(PublicKey kmk) {
            this.kmk = kmk;
        }

        public byte[] getAuthorization() {
            return authorization;
        }
    }

    private KeyManagementKeyUpdateHolder kmkRoot = new KeyManagementKeyUpdateHolder(null);

    public KeyManagementKeyUpdateHolder getKeyManagementKeyUpdateHolderRoot() {
        return kmkRoot;
    }

    String sessionKeyAlgorithm;

    public String getServerSessionId() {
        return serverSessionId;
    }


    public Date getServerTime() {
        return serverTime;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public ECPublicKey getServerEphemeralKey() {
        return serverEphemeralKey;
    }


    public String getSessionKeyAlgorithm() {
        return sessionKeyAlgorithm;
    }


    public int getSessionLifeTime() {
        return sessionLifeTime;
    }


    public short getSessionKeyLimit() {
        return sessionKeyLimit;
    }


    PublicKey keyManagementKey;

    public PublicKey getKeyManagementKey() {
        return keyManagementKey;
    }


    public String getVirtualEnvironmentFriendlyName() {
        return virtualEnvironmentFriendlyName;
    }


    private void scanForUpdateKeys(JSONObjectReader rd, KeyManagementKeyUpdateHolder kmk) throws IOException {
        if (rd.hasProperty(UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)) {
            JSONArrayReader updArr = rd.getArray(UPDATABLE_KEY_MANAGEMENT_KEYS_JSON);
            do {
                JSONObjectReader kmkUpd = updArr.getObject();
                byte[] authorization = kmkUpd.getBinary(AUTHORIZATION_JSON);
                KeyManagementKeyUpdateHolder child = new KeyManagementKeyUpdateHolder(kmkUpd.getPublicKey());
                child.authorization = authorization;
                kmk.children.add(child);
                scanForUpdateKeys(kmkUpd, child);
            }
            while (updArr.hasMore());
        }
    }

    String serverSessionId;

    byte[] nonce;

    Date serverTime;

    String serverTimeVerbatim;

    String submitUrl;

    ECPublicKey serverEphemeralKey;

    byte[] virtualEnvironmentData;

    String virtualEnvironmentType;

    String virtualEnvironmentFriendlyName;  // Optional, defined => Virtual environment defined

    int sessionLifeTime;

    short sessionKeyLimit;


    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Core session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        sessionKeyAlgorithm = rd.getString(SESSION_KEY_ALGORITHM_JSON);

        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        serverTimeVerbatim = rd.getString(SERVER_TIME_JSON);

        serverTime = ISODateTime.parseDateTime(serverTimeVerbatim).getTime();

        submitUrl = getURL(rd, SUBMIT_URL_JSON);

        sessionKeyLimit = (short) rd.getInt(SESSION_KEY_LIMIT_JSON);

        sessionLifeTime = rd.getInt(SESSION_LIFE_TIME_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        serverEphemeralKey = (ECPublicKey) rd.getObject(SERVER_EPHEMERAL_KEY_JSON).getPublicKey();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional key management key
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty(KEY_MANAGEMENT_KEY_JSON)) {
            JSONObjectReader kmkrd = rd.getObject(KEY_MANAGEMENT_KEY_JSON);
            keyManagementKey = kmkrd.getPublicKey();
            scanForUpdateKeys(kmkrd, kmkRoot = new KeyManagementKeyUpdateHolder(keyManagementKey));
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional virtual environment
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty(VIRTUAL_ENVIRONMENT_JSON)) {
            //TODO
            rd.getBinaryConditional(NONCE_JSON);
            if (!rd.hasProperty(JSONSignatureDecoder.SIGNATURE_JSON)) {
                throw new IOException("Virtual Environment requests must be signed");
            }
            JSONObjectReader vmrd = rd.getObject(VIRTUAL_ENVIRONMENT_JSON);
            virtualEnvironmentData = vmrd.getBinary(CONFIGURATION_JSON);
            virtualEnvironmentType = vmrd.getString(TYPE_JSON);
            virtualEnvironmentFriendlyName = vmrd.getString(FRIENDLY_NAME_JSON);
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_REQUEST.getName();
    }
}

