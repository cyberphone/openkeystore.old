/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
namespace org.webpki.sks.ws.client
{
    using System.Collections.Generic;

    using System.Security.Cryptography.X509Certificates;
    
    using org.webpki.sks.ws.client.BouncyCastle.Asn1;
    
    internal class Conversions
    {
        internal static byte[] encode_x509_public_key (PublicKey public_key, bool ec_flag)
        {
            if (public_key == null)
            {
                return null;
            }
            DerSequence inside = new DerSequence (new DerObjectIdentifier(public_key.Oid.Value));
            Asn1StreamParser asp = new Asn1StreamParser(public_key.EncodedParameters.RawData);
            IAsn1Convertible ro;
            while ((ro = asp.ReadObject()) != null)
            {
                inside.AddObject(ro.ToAsn1Object());
            }
            return new DerSequence(inside, new DerBitString(public_key.EncodedKeyValue.RawData)).GetEncoded();
        }

        public static byte[] encode_x509_public_key (PublicKey public_key)
        {
            return encode_x509_public_key (public_key, false);
        }

        public static byte[] encode_x509_ec_public_key (PublicKey public_key)
        {
            return encode_x509_public_key (public_key, true);
        }

        public static X509Certificate2[] blist2certs (List<byte[]> blist)
        {
            X509Certificate2[] certs = new X509Certificate2[blist.Count];
            int i = 0;
            foreach (byte[] b_arr in blist)
            {
                certs[i++] = new X509Certificate2(b_arr);
            }
            return i == 0 ? null : certs;
        }

        public static List<byte[]> certs2blist (X509Certificate2[] certs)
        {
            List<byte[]> blist = new List<byte[]>();
            if (certs != null) foreach (X509Certificate2 cert in certs)
            {
                blist.Add (cert.RawData);
            }
            return blist;
        }
    }
}