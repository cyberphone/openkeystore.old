import json
import collections

dual_signed = (
'{"@context":"http://xmlns.webpki.org/wcpp-payment-demo","@qualifier":"Transaction'
'Response","PaymentRequest":{"CommonName":"Demo Merchant","Amount":8600550,"Currenc'
'y":"USD","ReferenceID":"#1000001","DateTime":"2014-10-23T07:59:13Z","Signature":{"'
'Algorithm":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","KeyInfo":{"Signatu'
'reCertificate":{"Issuer":"CN=Merchant Network Sub CA5,C=DE","SerialNumber":"141398'
'3542582","Subject":"CN=Demo Merchant,2.5.4.5=#1306383936333235,C=DE"},"X509Certifi'
'catePath":["MIIDQzCCAiugAwIBAgIGAUk3_J02MA0GCSqGSIb3DQEBCwUAMDAxCzAJBgNVBAYTAkRFMS'
'EwHwYDVQQDExhNZXJjaGFudCBOZXR3b3JrIFN1YiBDQTUwHhcNMTQwMTAxMDAwMDAwWhcNMjAwNzEwMDk1'
'OTU5WjA2MQswCQYDVQQGEwJERTEPMA0GA1UEBRMGODk2MzI1MRYwFAYDVQQDEw1EZW1vIE1lcmNoYW50MI'
'IBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W4Gz1CMWkS634xBeZfraJvEKGUDUe_Hhi_F6yXd'
'q0TlJEX3XpLwlje5Tl8YCINRtPxvOTC-GKOf_XAp0mmEiZZN5LjdQlbRFwQZYa4ltkhb6xa0_uyk7o2Ara'
'agkRJvUBCBMy7NSFLKoQcZCGUainUugYue0Jxg3PVnQ5tdHs78cD2MDjRAn8HW45CpbbB8sXIwI2t3fbjK'
'I4by8OQpaR3j-EhdxZT2Ig0gFS4sL4XlgD88wNLArjtJUZZttxZGEM7aGRyOI8VismAmbo3jwr5uU2G1nH'
'AqQ-iI9kS056WSHSq2e_k3HIjH2B9K8T9Smwu0bYo-2L4LAyYYLbNBwQIDAQABo10wWzAJBgNVHRMEAjAA'
'MA4GA1UdDwEB_wQEAwID-DAdBgNVHQ4EFgQUIHSgwq-l-ZyC32odON_t9fc2nUcwHwYDVR0jBBgwFoAUwd'
'vh1RjfhNG59t4a-AWqbaTwbcAwDQYJKoZIhvcNAQELBQADggEBAAtcvMm-wifzGaawzFs1ikF7B48mnAeN'
'_cySxyvjD7gaQ6zmuGx_FM40WEvabTkN24tBo0FiXILCnAidybAirXvnz9I2VcAcJIBPbpqOQnBEUbXfwp'
'9g39DyEdYaYas8tNx8OzHulAKgJ8df4nzGRaCEj2xqzCJscdE6LvnSlb-56NWr8Ix9xdr5yjYSvPsgYBwh'
'fpooRitHrALbwPsDhdXhtafBX63oxaXV-ezYbiuE0VLV4IyS3l7c2RABt_TPDguubl16upGM9eV42YcQuq'
'jsCV6bfxLHRZx9fY6j97YnDY2cHMMGP3eMGlY734U3NasQfAhTUhxrdDbphEvsWTc","MIIEPzCCAiegAw'
'IBAgIBBTANBgkqhkiG9w0BAQ0FADAxMQswCQYDVQQGEwJVUzEiMCAGA1UEAxMZTWVyY2hhbnQgTmV0d29y'
'ayBSb290IENBMTAeFw0xMjA3MTAxMDAwMDBaFw0yNTA3MTAwOTU5NTlaMDAxCzAJBgNVBAYTAkRFMSEwHw'
'YDVQQDExhNZXJjaGFudCBOZXR3b3JrIFN1YiBDQTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB'
'AQCpNgu70pokHcysVBUrmRx_in7pqCxcpbop2dMU8VFlrmiS1WyqaDfZi_vHZNLaQ6cUbBvSrIhaH6R4V-'
'wIqgAEWkT8ZKztXzq2dEn59ljiS7i0F8STGiR5WPO-MvUODAHml3FSJxa60cpA9QtEdoaoiK39SxnPbZyd'
'grwFHAhavM-GOGJugkC2DbD4jp-7AHQFTq12pau4Sop0ZElWjW7O-XIDa00mhCNTRETurgpZPIo9MzTVES'
'dZXfEfw7Zw01Aq33sx2rTIYVcogpM1Xxxzx35rwBuskwNMmdSnb-tcqs5NnACIBKyocOhOpIHxZwTdnk_L'
'46UG7ebEJg3S8EqtAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgEGMB0GA1UdDg'
'QWBBTB2-HVGN-E0bn23hr4BaptpPBtwDAfBgNVHSMEGDAWgBT3vAmyC88zfK18WCj8EByigwFEZTANBgkq'
'hkiG9w0BAQ0FAAOCAgEAYa2n7JCxnnD0FK-zdd6dPl8B4g8EqgBPf9b4snpp6rXSu3X3fdN1Un7QChKwVx'
'YbfAUkviktZVQgaVzNkcDXu9QnNrK97m4_j8HhioRvMmXpuWcWkL94gxNMwFqpytAZnzd6m5Du9dMiRWuP'
'VwuLGEZ3-TlnOFi6Gnlmg1PuZEo9pySo_wC_iOYc-F7vM5SkbB5bCPxQbQZhW_eXPmLSpiwMBWFajcVT_8'
'xEVNpnDdtFiKMR-53-r8yYfNIU8gkehdg0BCRIgaQlu178A2Z8rLp_zsFFSQVaA1vGUjU5ZQp559r4CYY-'
'fEj25kRR3huL0MsmBDxrDYRh9DGV0NPPimWkfazEP00lNde3pj7OlZj7Yx5Mtyk3wuQ_N78TTfOoNmhOIo'
'6pbbaWDewTodQ5G2KWG7Gb8Ocrf_oGjJ333KptE7SACqb9OdK_d2OYM6X5skWqbqyxtpVTJ6BepjkOqiyp'
'SE660S2ecePiaG_sO3YgFmToBQDQ3_zH4fkWfXtdCiSY5k7MjawYrfcyO81gxSWtJ0qfKdu5ZOR2H72jjc'
'gaEjJ4TN6n6XUFYGRDkB2X1PrEmOe5gBwgw2Us3GB5_gxBOT__fThPkbleTC1-2_uXTz0PZOBh0OLJrG0r'
'zREg4u8NhVaIN3GU1IyRGA7IbdHOeDB2RUpsXloU2QKfLrk"]},"SignatureValue":"nGbFXnDEWcBuE'
'FAuT4Yp4wXoujprE5iWsKbCUiNeZICVr6Phc_ABlRaia9PAXgMUiSC8oEQszNypNn68vw8ETjeJM1_2Bgo'
'Yp38TeYcvsRRWNdXN4ERhRGX7OR1aEGPMJYtCKkZ-j9YblvC1eDUN-_vNf2QYBTWn4M8fOC4GFhsHrzZsZ'
'XIyEa5PTIvygohTYswEEangCO7BVdI4gLZSWqy4u4wfCjPfAQ2f6UpIyKAOa8tGmutMHNgZZOHI5iqkKp_'
'eIj-kB8JULTe5gP54Iy2emrgKWLrPmmfGwocEIX31SpPPh1g8J_NhlxSEFy81_h08b4RTucdSJaSu64GA_'
'Q"}},"CardType":"SuperCard","PaymentToken":"5bBrMt2gSQy9YY45aqLYsfWcHz05VBv-ACr8Es'
'_Vzug","ReferencePAN":"**** **** **** 1078","TransactionID":"#164007","DateTime":"'
'2014-10-23T08:01:31Z","Signature":{"Algorithm":"http://www.w3.org/2001/04/xmldsig-'
'more#ecdsa-sha256","KeyInfo":{"SignatureCertificate":{"Issuer":"CN=Payment Network'
' Sub CA3,C=EU","SerialNumber":"1413983531532","Subject":"CN=mybank.com,2.5.4.5=#13'
'0434353031,C=FR"},"X509CertificatePath":["MIIBtTCCAVmgAwIBAgIGAUk3_HIMMAwGCCqGSM49'
'BAMCBQAwLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMB4XDTE0MD'
'EwMTAwMDAwMFoXDTIwMDcxMDA5NTk1OVowMTELMAkGA1UEBhMCRlIxDTALBgNVBAUTBDQ1MDExEzARBgNV'
'BAMTCm15YmFuay5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT1zJg9CWv_4teTWss_hvrNk9uXFv'
'YJXmFEEx79ceC9D4uQVAMiQIonFdwZ28qG-Cvd4JHbulaaI9h5i2R-U0lbo10wWzAJBgNVHRMEAjAAMA4G'
'A1UdDwEB_wQEAwID-DAdBgNVHQ4EFgQUUQir5Sd5r2lSsYQiu4dIZU-_3pswHwYDVR0jBBgwFoAU6Xx-G1'
'iq2pE5kkPoWqcdj4N-CUgwDAYIKoZIzj0EAwIFAANIADBFAiEA7DancGSJ0DpVyJVW3M_jYfMhPww5d7Wg'
'P1Z2ctndVnACIChhLAqHLo6TQGxSiOHEcgmBReQDW1xKjAKQPs4o4Sv9","MIIDcjCCAVqgAwIBAgIBAzA'
'NBgkqhkiG9w0BAQ0FADAwMQswCQYDVQQGEwJVUzEhMB8GA1UEAxMYUGF5bWVudCBOZXR3b3JrIFJvb3QgQ'
'0ExMB4XDTEyMDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1B'
'heW1lbnQgTmV0d29yayBTdWIgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWnpYyopR0exWLo4KO'
'I0_qDw1u44RudHpmeZAMA1iVfOYkKTYeuXHHVFcloH9zRf4x04tmJPegrmBEQPJt8e8oKNjMGEwDwYDVR0'
'TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOl8fhtYqtqROZJD6FqnHY-DfglIMB8GA'
'1UdIwQYMBaAFGc8kmIhLpXZAyUOw4Luf4ELyYawMA0GCSqGSIb3DQEBDQUAA4ICAQCDsUzatKF182VKMm8'
'kmLhvZ19FBw6mNoatAdBHNjVnhcc51-m-9H9dX_JPz143fa4LVCQehnC1VzIGNS0wIfIQS9F2YBiae47cI'
'InjDL22AMg9TgOWapp94sTDSLV_NgFtPQKZ4I_E8qinn57LyRYEVaGkk1eXP6HCHbjOIt2zRuBnlOyIh4z'
'JuMmLwW95Yi2VWLubmHFDr2B_sKtKjmmsJ6IkSfeP-FAjTjLgGHsBvhiiHrhvPuG0PhnN3WWYv5bmOviuU'
'R8vl-QbzCnyx8AfBzlVA_6gpS9tDwD_-CalGa4srjD4VZ9LJ9tcUuSNEjxtYCqBAGmdZKdWhczD4sH5c5X'
'wT1ttBKEMhPR_HwNei8GiHi009yXOTG8VVyf-sriBAP4QGytBOYhwTmYyxH3csOkkZ8kV299J90kZg_kUS'
'NVdO1k2TFBNfb7bqi2lrUYr_vrpauxWyGMcxOHuxI2ID3IFONQroqxrrnRj8bEsjVV23ed-NACk7ubXLdO'
'MjaBlrXOoWsLxW232pnB0qo6-9tHy5MpSnjzM4s5cMw1qjCij_0rSDewSwcK0quPGFaw6cEPwTDAd28HFx'
'f5WzI3YJb9QAtIe0LUyl4_S3LO98wxnCtZtTxk3Av0XetLFxvRpQJa7IZo85f-51qjNngHV7ZB7BXkA49f'
'98QyM_VJs3w"]},"SignatureValue":"MEQCIGU3VRMpkzX-JArW-AzBsqsLjWszmg1lRRz0XYHj5GIcA'
'iBE6pPG43EU3xPGgONkkRrP3KK44U0hK8I_1rLuDgVQfQ"}}')

dual_signature_json_normalized = (
'{"@context":"http://xmlns.webpki.org/wcpp-payment-demo","@qualifier":"Transaction'
'Response","PaymentRequest":{"CommonName":"Demo Merchant","Amount":8600550,"Currenc'
'y":"USD","ReferenceID":"#1000001","DateTime":"2014-10-23T07:59:13Z","Signature":{"'
'Algorithm":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","KeyInfo":{"Signatu'
'reCertificate":{"Issuer":"CN=Merchant Network Sub CA5,C=DE","SerialNumber":"141398'
'3542582","Subject":"CN=Demo Merchant,2.5.4.5=#1306383936333235,C=DE"},"X509Certifi'
'catePath":["MIIDQzCCAiugAwIBAgIGAUk3_J02MA0GCSqGSIb3DQEBCwUAMDAxCzAJBgNVBAYTAkRFMS'
'EwHwYDVQQDExhNZXJjaGFudCBOZXR3b3JrIFN1YiBDQTUwHhcNMTQwMTAxMDAwMDAwWhcNMjAwNzEwMDk1'
'OTU5WjA2MQswCQYDVQQGEwJERTEPMA0GA1UEBRMGODk2MzI1MRYwFAYDVQQDEw1EZW1vIE1lcmNoYW50MI'
'IBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W4Gz1CMWkS634xBeZfraJvEKGUDUe_Hhi_F6yXd'
'q0TlJEX3XpLwlje5Tl8YCINRtPxvOTC-GKOf_XAp0mmEiZZN5LjdQlbRFwQZYa4ltkhb6xa0_uyk7o2Ara'
'agkRJvUBCBMy7NSFLKoQcZCGUainUugYue0Jxg3PVnQ5tdHs78cD2MDjRAn8HW45CpbbB8sXIwI2t3fbjK'
'I4by8OQpaR3j-EhdxZT2Ig0gFS4sL4XlgD88wNLArjtJUZZttxZGEM7aGRyOI8VismAmbo3jwr5uU2G1nH'
'AqQ-iI9kS056WSHSq2e_k3HIjH2B9K8T9Smwu0bYo-2L4LAyYYLbNBwQIDAQABo10wWzAJBgNVHRMEAjAA'
'MA4GA1UdDwEB_wQEAwID-DAdBgNVHQ4EFgQUIHSgwq-l-ZyC32odON_t9fc2nUcwHwYDVR0jBBgwFoAUwd'
'vh1RjfhNG59t4a-AWqbaTwbcAwDQYJKoZIhvcNAQELBQADggEBAAtcvMm-wifzGaawzFs1ikF7B48mnAeN'
'_cySxyvjD7gaQ6zmuGx_FM40WEvabTkN24tBo0FiXILCnAidybAirXvnz9I2VcAcJIBPbpqOQnBEUbXfwp'
'9g39DyEdYaYas8tNx8OzHulAKgJ8df4nzGRaCEj2xqzCJscdE6LvnSlb-56NWr8Ix9xdr5yjYSvPsgYBwh'
'fpooRitHrALbwPsDhdXhtafBX63oxaXV-ezYbiuE0VLV4IyS3l7c2RABt_TPDguubl16upGM9eV42YcQuq'
'jsCV6bfxLHRZx9fY6j97YnDY2cHMMGP3eMGlY734U3NasQfAhTUhxrdDbphEvsWTc","MIIEPzCCAiegAw'
'IBAgIBBTANBgkqhkiG9w0BAQ0FADAxMQswCQYDVQQGEwJVUzEiMCAGA1UEAxMZTWVyY2hhbnQgTmV0d29y'
'ayBSb290IENBMTAeFw0xMjA3MTAxMDAwMDBaFw0yNTA3MTAwOTU5NTlaMDAxCzAJBgNVBAYTAkRFMSEwHw'
'YDVQQDExhNZXJjaGFudCBOZXR3b3JrIFN1YiBDQTUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB'
'AQCpNgu70pokHcysVBUrmRx_in7pqCxcpbop2dMU8VFlrmiS1WyqaDfZi_vHZNLaQ6cUbBvSrIhaH6R4V-'
'wIqgAEWkT8ZKztXzq2dEn59ljiS7i0F8STGiR5WPO-MvUODAHml3FSJxa60cpA9QtEdoaoiK39SxnPbZyd'
'grwFHAhavM-GOGJugkC2DbD4jp-7AHQFTq12pau4Sop0ZElWjW7O-XIDa00mhCNTRETurgpZPIo9MzTVES'
'dZXfEfw7Zw01Aq33sx2rTIYVcogpM1Xxxzx35rwBuskwNMmdSnb-tcqs5NnACIBKyocOhOpIHxZwTdnk_L'
'46UG7ebEJg3S8EqtAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgEGMB0GA1UdDg'
'QWBBTB2-HVGN-E0bn23hr4BaptpPBtwDAfBgNVHSMEGDAWgBT3vAmyC88zfK18WCj8EByigwFEZTANBgkq'
'hkiG9w0BAQ0FAAOCAgEAYa2n7JCxnnD0FK-zdd6dPl8B4g8EqgBPf9b4snpp6rXSu3X3fdN1Un7QChKwVx'
'YbfAUkviktZVQgaVzNkcDXu9QnNrK97m4_j8HhioRvMmXpuWcWkL94gxNMwFqpytAZnzd6m5Du9dMiRWuP'
'VwuLGEZ3-TlnOFi6Gnlmg1PuZEo9pySo_wC_iOYc-F7vM5SkbB5bCPxQbQZhW_eXPmLSpiwMBWFajcVT_8'
'xEVNpnDdtFiKMR-53-r8yYfNIU8gkehdg0BCRIgaQlu178A2Z8rLp_zsFFSQVaA1vGUjU5ZQp559r4CYY-'
'fEj25kRR3huL0MsmBDxrDYRh9DGV0NPPimWkfazEP00lNde3pj7OlZj7Yx5Mtyk3wuQ_N78TTfOoNmhOIo'
'6pbbaWDewTodQ5G2KWG7Gb8Ocrf_oGjJ333KptE7SACqb9OdK_d2OYM6X5skWqbqyxtpVTJ6BepjkOqiyp'
'SE660S2ecePiaG_sO3YgFmToBQDQ3_zH4fkWfXtdCiSY5k7MjawYrfcyO81gxSWtJ0qfKdu5ZOR2H72jjc'
'gaEjJ4TN6n6XUFYGRDkB2X1PrEmOe5gBwgw2Us3GB5_gxBOT__fThPkbleTC1-2_uXTz0PZOBh0OLJrG0r'
'zREg4u8NhVaIN3GU1IyRGA7IbdHOeDB2RUpsXloU2QKfLrk"]}'
'}},"CardType":"SuperCard","PaymentToken":"5bBrMt2gSQy9YY45aqLYsfWcHz05VBv-ACr8Es'
'_Vzug","ReferencePAN":"**** **** **** 1078","TransactionID":"#164007","DateTime":"'
'2014-10-23T08:01:31Z","Signature":{"Algorithm":"http://www.w3.org/2001/04/xmldsig-'
'more#ecdsa-sha256","KeyInfo":{"SignatureCertificate":{"Issuer":"CN=Payment Network'
' Sub CA3,C=EU","SerialNumber":"1413983531532","Subject":"CN=mybank.com,2.5.4.5=#13'
'0434353031,C=FR"},"X509CertificatePath":["MIIBtTCCAVmgAwIBAgIGAUk3_HIMMAwGCCqGSM49'
'BAMCBQAwLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMB4XDTE0MD'
'EwMTAwMDAwMFoXDTIwMDcxMDA5NTk1OVowMTELMAkGA1UEBhMCRlIxDTALBgNVBAUTBDQ1MDExEzARBgNV'
'BAMTCm15YmFuay5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT1zJg9CWv_4teTWss_hvrNk9uXFv'
'YJXmFEEx79ceC9D4uQVAMiQIonFdwZ28qG-Cvd4JHbulaaI9h5i2R-U0lbo10wWzAJBgNVHRMEAjAAMA4G'
'A1UdDwEB_wQEAwID-DAdBgNVHQ4EFgQUUQir5Sd5r2lSsYQiu4dIZU-_3pswHwYDVR0jBBgwFoAU6Xx-G1'
'iq2pE5kkPoWqcdj4N-CUgwDAYIKoZIzj0EAwIFAANIADBFAiEA7DancGSJ0DpVyJVW3M_jYfMhPww5d7Wg'
'P1Z2ctndVnACIChhLAqHLo6TQGxSiOHEcgmBReQDW1xKjAKQPs4o4Sv9","MIIDcjCCAVqgAwIBAgIBAzA'
'NBgkqhkiG9w0BAQ0FADAwMQswCQYDVQQGEwJVUzEhMB8GA1UEAxMYUGF5bWVudCBOZXR3b3JrIFJvb3QgQ'
'0ExMB4XDTEyMDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowLzELMAkGA1UEBhMCRVUxIDAeBgNVBAMTF1B'
'heW1lbnQgTmV0d29yayBTdWIgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWnpYyopR0exWLo4KO'
'I0_qDw1u44RudHpmeZAMA1iVfOYkKTYeuXHHVFcloH9zRf4x04tmJPegrmBEQPJt8e8oKNjMGEwDwYDVR0'
'TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOl8fhtYqtqROZJD6FqnHY-DfglIMB8GA'
'1UdIwQYMBaAFGc8kmIhLpXZAyUOw4Luf4ELyYawMA0GCSqGSIb3DQEBDQUAA4ICAQCDsUzatKF182VKMm8'
'kmLhvZ19FBw6mNoatAdBHNjVnhcc51-m-9H9dX_JPz143fa4LVCQehnC1VzIGNS0wIfIQS9F2YBiae47cI'
'InjDL22AMg9TgOWapp94sTDSLV_NgFtPQKZ4I_E8qinn57LyRYEVaGkk1eXP6HCHbjOIt2zRuBnlOyIh4z'
'JuMmLwW95Yi2VWLubmHFDr2B_sKtKjmmsJ6IkSfeP-FAjTjLgGHsBvhiiHrhvPuG0PhnN3WWYv5bmOviuU'
'R8vl-QbzCnyx8AfBzlVA_6gpS9tDwD_-CalGa4srjD4VZ9LJ9tcUuSNEjxtYCqBAGmdZKdWhczD4sH5c5X'
'wT1ttBKEMhPR_HwNei8GiHi009yXOTG8VVyf-sriBAP4QGytBOYhwTmYyxH3csOkkZ8kV299J90kZg_kUS'
'NVdO1k2TFBNfb7bqi2lrUYr_vrpauxWyGMcxOHuxI2ID3IFONQroqxrrnRj8bEsjVV23ed-NACk7ubXLdO'
'MjaBlrXOoWsLxW232pnB0qo6-9tHy5MpSnjzM4s5cMw1qjCij_0rSDewSwcK0quPGFaw6cEPwTDAd28HFx'
'f5WzI3YJb9QAtIe0LUyl4_S3LO98wxnCtZtTxk3Av0XetLFxvRpQJa7IZo85f-51qjNngHV7ZB7BXkA49f'
'98QyM_VJs3w"]},"SignatureValue":"MEQCIGU3VRMpkzX-JArW-AzBsqsLjWszmg1lRRz0XYHj5GIcA'
'iBE6pPG43EU3xPGgONkkRrP3KK44U0hK8I_1rLuDgVQfQ"}}')



my_ordered_dict = json.loads(dual_signed, object_pairs_hook=collections.OrderedDict)
parsed_signature = json.dumps(my_ordered_dict,separators=(',',':'))
print parsed_signature
my_ordered_dict['PaymentRequest']['Signature'].pop('SignatureValue')
modified_signature = json.dumps(my_ordered_dict,separators=(',',':'))
print modified_signature
print modified_signature == dual_signature_json_normalized
