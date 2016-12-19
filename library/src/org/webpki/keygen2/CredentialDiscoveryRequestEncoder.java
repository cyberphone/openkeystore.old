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
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Vector;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectWriter;
import org.webpki.keygen2.ServerState.ProtocolPhase;
import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    ServerCryptoInterface server_crypto_interface;

    String submit_url;

    String server_session_id;

    String client_session_id;

    public class LookupDescriptor extends CertificateFilter implements AsymKeySignerInterface {

        PublicKey key_management_key;

        String id;

        boolean search_filter;

        Date issued_before;
        Date issued_after;
        Grouping grouping;
        AppUsage app_usage;

        LookupDescriptor(PublicKey key_management_key) {
            this.key_management_key = key_management_key;
            this.id = lookup_prefix + ++next_lookup_id_suffix;
        }

        @Override
        protected void nullCheck(Object object) throws IOException {
            search_filter = true;
            if (object == null) {
                bad("Null search parameter not allowed");
            }
        }


        public LookupDescriptor setIssuedBefore(Date issued_before) throws IOException {
            nullCheck(issued_before);
            search_filter = true;
            this.issued_before = issued_before;
            return this;
        }

        public LookupDescriptor setIssuedAfter(Date issued_after) throws IOException {
            nullCheck(issued_after);
            search_filter = true;
            this.issued_after = issued_after;
            return this;
        }

        public LookupDescriptor setGrouping(Grouping grouping) throws IOException {
            nullCheck(grouping);
            search_filter = true;
            this.grouping = grouping;
            return this;
        }

        public LookupDescriptor setAppUsage(AppUsage app_usage) throws IOException {
            nullCheck(app_usage);
            search_filter = true;
            this.app_usage = app_usage;
            return this;
        }

        void write(JSONObjectWriter wr) throws IOException {
            wr.setString(ID_JSON, id);

            wr.setBinary(NONCE_JSON, nonce);

            if (search_filter) {
                JSONObjectWriter search_writer = wr.setObject(SEARCH_FILTER_JSON);
                setOptionalBinary(search_writer, CertificateFilter.CF_FINGER_PRINT, getFingerPrint());
                setOptionalString(search_writer, CertificateFilter.CF_ISSUER_REG_EX, getIssuerRegEx());
                setOptionalBigInteger(search_writer, CertificateFilter.CF_SERIAL_NUMBER, getSerialNumber());
                setOptionalString(search_writer, CertificateFilter.CF_SUBJECT_REG_EX, getSubjectRegEx());
                setOptionalString(search_writer, CertificateFilter.CF_EMAIL_REG_EX, getEmailRegEx());
                setOptionalStringArray(search_writer, CertificateFilter.CF_POLICY_RULES, getPolicyRules());
                setOptionalStringArray(search_writer, CertificateFilter.CF_KEY_USAGE_RULES, getKeyUsageRules());
                setOptionalStringArray(search_writer, CertificateFilter.CF_EXT_KEY_USAGE_RULES, getExtendedKeyUsageRules());
                setOptionalDateTime(search_writer, ISSUED_BEFORE_JSON, issued_before);
                setOptionalDateTime(search_writer, ISSUED_AFTER_JSON, issued_after);
                if (grouping != null) {
                    search_writer.setString(GROUPING_JSON, grouping.getProtocolName());
                }
                if (app_usage != null) {
                    search_writer.setString(APP_USAGE_JSON, app_usage.getProtocolName());
                }
            }
            JSONAsymKeySigner signer = new JSONAsymKeySigner(this);
            signer.setSignatureAlgorithm(key_management_key instanceof RSAPublicKey ?
                    AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256);
            wr.setSignature(signer);
        }

        @Override
        public PublicKey getPublicKey() throws IOException {
            return key_management_key;
        }

        @Override
        public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
            return server_crypto_interface.generateKeyManagementAuthorization(key_management_key, data);
        }
    }


    Vector<LookupDescriptor> lookup_descriptors = new Vector<LookupDescriptor>();

    String lookup_prefix = "Lookup.";

    byte[] nonce;

    int next_lookup_id_suffix = 0;

    // Constructors

    public CredentialDiscoveryRequestEncoder(ServerState server_state, String submit_url) throws IOException {
        server_state.checkState(true, ProtocolPhase.CREDENTIAL_DISCOVERY);
        client_session_id = server_state.client_session_id;
        server_session_id = server_state.server_session_id;
        server_crypto_interface = server_state.server_crypto_interface;
        this.submit_url = submit_url;
    }


    public LookupDescriptor addLookupDescriptor(PublicKey key_management_key) {
        LookupDescriptor lo_des = new LookupDescriptor(key_management_key);
        lookup_descriptors.add(lo_des);
        return lo_des;
    }


    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, server_session_id);

        wr.setString(CLIENT_SESSION_ID_JSON, client_session_id);

        wr.setString(SUBMIT_URL_JSON, submit_url);

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookup_descriptors.isEmpty()) {
            bad("There must be at least one descriptor defined");
        }
        MacGenerator concat = new MacGenerator();
        concat.addString(client_session_id);
        concat.addString(server_session_id);
        nonce = HashAlgorithms.SHA256.digest(concat.getResult());
        JSONArrayWriter array = wr.setArray(LOOKUP_SPECIFIERS_JSON);
        for (LookupDescriptor im_des : lookup_descriptors) {
            im_des.write(array.setObject());
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.CREDENTIAL_DISCOVERY_REQUEST.getName();
    }
}
