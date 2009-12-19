package org.webpki.sks;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.util.ServiceLoader;
import java.util.Vector;

import org.webpki.util.StringUtil;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.crypto.CertificateUtil;

import org.webpki.keygen2.PassphraseFormats;



public class KeyUtil
  {
    private static ServiceLoader<DatabaseService> database_service = ServiceLoader.load (DatabaseService.class);

    public static byte[] getCRC16 (byte[] testBytes)
      {
        short crc = (short) 0xFFFF;       // initial contents of LFBSR
        for (int j = 0; j < testBytes.length; j++)
          {
            byte c = testBytes[j];
            for (int i = 0; i < 8; i++)
              {
                boolean c15 = ((crc >> 15      & 1) == 1);
                boolean bit = ((c   >> (7 - i) & 1) == 1);
                crc <<= 1;
                if (c15 ^ bit) crc ^= 0x1021;   // 0001 0000 0010 0001  (0, 5, 12)
              }
          }
        return new byte[]{(byte)(crc >> 8), (byte) (crc & 0xff)};
      }


    public static byte[] createDBCertificatePath (X509Certificate[] sorted_cert_path) throws IOException, GeneralSecurityException
      {
        byte[] cert_path_bytes = new byte[] {(byte) sorted_cert_path.length};
        for (X509Certificate cert : sorted_cert_path)
          {
            byte[] cert_bytes = cert.getEncoded ();
            cert_path_bytes = ArrayUtil.add (cert_path_bytes,
                                             ArrayUtil.add (new byte[]{(byte)(cert_bytes.length >>> 8), (byte)(cert_bytes.length & 0xFF)},
                                                            cert_bytes));
          }
        return cert_path_bytes;
      }


    public static X509Certificate[] restoreCertificatePathFromDB (byte[] encoded_cert_path) throws IOException
      {
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        int n = encoded_cert_path[0];
        int i = 1;
        while (n-- > 0)
          {
            int l = (encoded_cert_path[i++] << 8) + (encoded_cert_path[i++] & 0xFF);
            byte[] certificate = new byte[l];
            System.arraycopy (encoded_cert_path, i, certificate, 0, l);
            certificates.add (CertificateUtil.getCertificateFromBlob (certificate));
            i += l;
          }
        return certificates.toArray (new X509Certificate[0]);
      }


    static byte[] getPassphrase (String passphrase, PassphraseFormats format) throws IOException
      {
        return format == PassphraseFormats.HEX2BYTES ?
                               DebugFormatter.getByteArrayFromHex (passphrase)
                                          :
                               passphrase.getBytes ("UTF-8");
      }


    static String[] getSupportedAlgorithms (String list_or_null)
      {
        return list_or_null == null ? null : StringUtil.tokenVector (list_or_null);
      }


    public static Connection getDatabaseConnection () throws SQLException
      {
        return database_service.iterator ().next ().getDatabaseConnection ();
      }


  }
