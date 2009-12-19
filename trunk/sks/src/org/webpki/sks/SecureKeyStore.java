package org.webpki.sks;

import java.io.IOException;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.MacAlgorithms;

import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyOperationRequestDecoder;


/**
 * This interface is the bridge between the cryptographic functions and the
 * Security&nbsp;Element.
 */
public interface SecureKeyStore
  {
    public boolean isSupported (String algorithm);

    public String[] getSupportedAlgorithms ();

    public String getDeviceName ();

    public interface AttestedKeyPair
      {
        public PublicKey getPublicKey ();

        public byte[] getPrivateKeyHandle ();

        public byte[] getAttestSignature ();

        public byte[] getEncryptedPrivateKey ();

        public byte[] getWrappedEncryptionKey ();
      }

    public AttestedKeyPair generateAttestedKeyPair (KeyOperationRequestDecoder.KeyAlgorithmData key_alg,
                                                    String attestation_algorithm,
                                                    boolean exportable,
                                                    KeyGen2KeyUsage key_usage,
                                                    byte[] nonce,
                                                    byte[] opt_archival_public_key,
                                                    String private_key_format_uri,
                                                    SymEncryptionAlgorithms encrytion_algorithm,
                                                    AsymEncryptionAlgorithms key_wrap_algorithm)
    throws IOException;

    public byte[] deviceKeyDecrypt (byte[] data, AsymEncryptionAlgorithms algorithm) throws IOException;
  

    public byte[] deviceKeyDigestSign (byte[] digest, SignatureAlgorithms algorithm) throws IOException;

    public X509Certificate[] getDeviceCertificatePath () throws IOException;

    public byte[] symmetricKeyHMAC (byte[] data,
                                    int key_id,
                                    MacAlgorithms algorithm,
                                    byte[] optional_pin,
                                    KeyAuthorizationCallback key_auth_callback)
    throws IOException;;

    public byte[] privateKeyDigestSign (byte[] digest,
                                        int key_id,
                                        SignatureAlgorithms algorithm,
                                        byte[] optional_pin,
                                        KeyAuthorizationCallback key_auth_callback)
    throws IOException;

    public byte[] symmetricKeyEncrypt (boolean encrypt_flag,
                                       byte[] data,
                                       int key_id,
                                       SymEncryptionAlgorithms algorithm,
                                       byte[] optional_iv,
                                       byte[] optional_pin,
                                       KeyAuthorizationCallback key_auth_callback)
    throws IOException;

    public byte[] privateKeyDecrypt (byte[] data,
                                     int key_id,
                                     AsymEncryptionAlgorithms algorithm,
                                     byte[] optional_pin,
                                     KeyAuthorizationCallback key_auth_callback)
    throws IOException;

    public byte[] sealPrivateKey (PrivateKey private_key,
                                  boolean exportable,
                                  KeyGen2KeyUsage key_usage) throws IOException;

    public byte[] sealSecretKey (byte[] secret_key,
                                 boolean exportable,
                                 String[] endorsed_algorithms) throws IOException;


    /**
     * Provisions a KeyGen2 "piggybacked" symmetric key. Below is an example:      
     * <pre>  &lt;<font color="#C00000">CertifiedPublicKey</font> <font color="#0000C0">ID</font>="Key.1"&gt;
     &lt;<font color="#008000">ds</font>:<font color="#C00000">X509Data</font>&gt;
        &lt;<font color="#008000">ds</font>:<font color="#C00000">X509Certificate</font>&gt;MIIDnTCCAo...fCc6PBLPWMYn4dPY=&lt;/<font color="#008000">ds</font>:<font color="#C00000">X509Certificate</font>&gt;
     &lt;/<font color="#008000">ds</font>:<font color="#C00000">X509Data</font>&gt;
     &lt;<font color="#C00000">PiggybackedSymmetricKey</font> <font color="#0000C0">EndorsedAlgorithms</font>="http://www.w3.org/2000/09/xmldsig#hmac-sha1"
                              <font color="#0000C0">MAC</font>="14z1RfdoVeDqYfSviPWZD4c2AL4="&gt;
        &lt;<font color="#008000">xenc</font>:<font color="#C00000">EncryptedKey</font>&gt;
           &lt;<font color="#008000">xenc</font>:<font color="#C00000">EncryptionMethod</font> <font color="#0000C0">Algorithm</font>="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/&gt;
           &lt;<font color="#008000">xenc</font>:<font color="#C00000">CipherData</font>&gt;
              &lt;<font color="#008000">xenc</font>:<font color="#C00000">CipherValue</font>&gt;VA2TbKUq...HQk9HoOIwCeSs=&lt;/<font color="#008000">xenc</font>:<font color="#C00000">CipherValue</font>&gt;
           &lt;/<font color="#008000">xenc</font>:<font color="#C00000">CipherData</font>&gt;
        &lt;/<font color="#008000">xenc</font>:<font color="#C00000">EncryptedKey</font>&gt;
     &lt;/<font color="#C00000">PiggybackedSymmetricKey</font>&gt;
  &lt;/<font color="#C00000">CertifiedPublicKey</font>&gt;
</pre>
<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="8" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">piggyback_mac_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Key &quot;piggyback&quot; MAC algorithm in local SE notation.&nbsp;
     * Currently only <code><nobr>http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-piggyback-1</nobr></code>
     * is supported</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encryption_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The XML encryption <code>Algorithm</code> expressed in local SE notation.&nbsp;
     * Currently only <code><nobr>http://www.w3.org/2001/04/xmlenc#rsa-1_5</nobr></code> is supported</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encrypted_symmetric_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The encrypted data as featured in the <code>CipherValue</code> element</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed private key associated with the <code>CertifiedPublicKey</code>
     * element embedding the <code>PiggybackedSymmetricKey</code> element</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">endorsed_algorithms</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">An array of SE-local identifiers to 
     * the <code>EndorsedAlgorithms</code> as declared in the <code>PiggybackedSymmetricKey</code> element
     * where the algorithm URIs have been sorted in alphabetical order</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">mac</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The <code>MAC</code> as declared in the
     * <code>PiggybackedSymmetricKey</code> element.
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">nonce</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Nonce data</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Sealed secret key</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public byte[] provisionPiggybackedSymmetricKey (String piggyback_mac_algorithm,
                                                    byte[] encrypted_symmetric_key,
                                                    byte[] private_key_handle,
                                                    AsymEncryptionAlgorithms encryption_algorithm,
                                                    String[] endorsed_algorithms,
                                                    byte[] declared_mac,
                                                    byte[] nonce)
    throws IOException;
    
  }
