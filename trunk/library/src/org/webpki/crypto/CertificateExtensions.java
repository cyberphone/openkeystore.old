package org.webpki.crypto;


public enum CertificateExtensions
  {
    SUBJECT_KEY_IDENTIFIER      ("2.5.29.14"),
    KEY_USAGE                   ("2.5.29.15"),
    SUBJECT_ALT_NAME            ("2.5.29.17"),
    BASIC_CONSTRAINTS           ("2.5.29.19"),
    CRL_DISTRIBUTION_POINTS     ("2.5.29.31"),
    CERTIFICATE_POLICIES        ("2.5.29.32"),
    AUTHORITY_KEY_IDENTIFIER    ("2.5.29.35"),
    AUTHORITY_INFO_ACCESS       ("1.3.6.1.5.5.7.1.1"),
    LOGOTYPES                   ("1.3.6.1.5.5.7.1.12");

    private final String oid;

    private CertificateExtensions (String oid)
      {
        this.oid = oid;
      }


    public String getOID ()
      {
        return oid;
      }

  }
