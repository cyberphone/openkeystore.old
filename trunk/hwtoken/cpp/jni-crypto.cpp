#include "webpki/crypto.h"
#include "jni-crypto.h"

using namespace webpki;

static void throwException (JNIEnv *env, const char *error)
  {
    jclass newExcCls = env->FindClass ("java/lang/RuntimeException");
    env->ThrowNew (newExcCls, error);
    env->DeleteLocalRef (newExcCls);
  }

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    createAESProvider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_AESProvider_createAESProvider (JNIEnv *env, jobject obj)
  {
    return reinterpret_cast<jlong>(new AESProvider ());
  }

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    deleteAESProvider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_AESProvider_deleteAESProvider (JNIEnv *env, jobject obj, jlong ptr)
  {
    delete reinterpret_cast<AESProvider *>(ptr);
  }

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    setKey
 * Signature: (J[BZ)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_AESProvider_setKey (JNIEnv *env, jobject obj, jlong ptr, jbyteArray j_raw_key, jboolean encrypt)
  {
    jbyte *c_raw_key = env->GetByteArrayElements (j_raw_key, NULL);
    jsize length_raw_key = env->GetArrayLength (j_raw_key);
    reinterpret_cast<AESProvider *>(ptr)->setKey ((unsigned char *)c_raw_key, length_raw_key, encrypt);
    env->ReleaseByteArrayElements (j_raw_key, c_raw_key, 0);
  }

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    encrypt
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_AESProvider_encrypt (JNIEnv *env, jobject obj, jlong ptr, jbyteArray j_data, jbyteArray j_iv, jboolean pad)
  {
    jbyte *c_data = env->GetByteArrayElements (j_data, NULL);
    jsize length_data = env->GetArrayLength (j_data);
    jbyte *c_iv = NULL;
    if (j_iv)
      {
        c_iv = env->GetByteArrayElements (j_iv, NULL);
      }
    unsigned char *out = new unsigned char[length_data + AESProvider::AES_BLOCK_SIZE];
    int in_out_len = length_data;
    const char *error = reinterpret_cast<AESProvider *>(ptr)->encrypt (out, in_out_len, (unsigned char *) c_data, (unsigned char *)c_iv, pad);
    env->ReleaseByteArrayElements (j_data, c_data, 0);
    if (j_iv)
      {
        env->ReleaseByteArrayElements (j_iv, c_iv, 0);
      }
    if (error)
      {
        delete out;
        throwException (env, error);
        return NULL;
      }
    jbyteArray j_result = env->NewByteArray (in_out_len);
    env->SetByteArrayRegion (j_result, 0, in_out_len, (jbyte *)out);
    delete out;
    return j_result;
  }

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    createSHA256Provider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_SHA256Provider_createSHA256Provider (JNIEnv *env, jobject jobj)
  {
    return reinterpret_cast<jlong>(new SHA256Provider ());
  }

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    deleteSHA256Provider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA256Provider_deleteSHA256Provider (JNIEnv *env, jobject jobj, jlong ptr)
  {
    delete reinterpret_cast<SHA256Provider *>(ptr);
  }

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    update
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA256Provider_update (JNIEnv *env, jobject jobj, jlong ptr, jbyteArray j_data)
  {
    jbyte *c_data = env->GetByteArrayElements (j_data, NULL);
    jsize length_data = env->GetArrayLength (j_data);
    reinterpret_cast<SHA256Provider *>(ptr)->update ((unsigned char *)c_data, length_data);
    env->ReleaseByteArrayElements (j_data, c_data, 0);
  }

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    doFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_SHA256Provider_doFinal (JNIEnv *env, jobject jobj, jlong ptr)
  {
    unsigned char out[SHA256Provider::DIGEST_LENGTH];
    const char *error = reinterpret_cast<SHA256Provider *>(ptr)->doFinal (out);
    if (error)
      {
        throwException (env, error);
        return NULL;
      }
    jbyteArray j_result = env->NewByteArray (SHA256Provider::DIGEST_LENGTH);
    env->SetByteArrayRegion (j_result, 0, SHA256Provider::DIGEST_LENGTH, (jbyte *)out);
    return j_result;
  }

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    createSHA1Provider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_SHA1Provider_createSHA1Provider (JNIEnv *env, jobject jobj)
  {
    return reinterpret_cast<jlong>(new SHA1Provider ());
  }

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    deleteSHA1Provider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA1Provider_deleteSHA1Provider (JNIEnv *env, jobject jobj, jlong ptr)
  {
    delete reinterpret_cast<SHA1Provider *>(ptr);
  }

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    update
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA1Provider_update (JNIEnv *env, jobject jobj, jlong ptr, jbyteArray j_data)
  {
    jbyte *c_data = env->GetByteArrayElements (j_data, NULL);
    jsize length_data = env->GetArrayLength (j_data);
    reinterpret_cast<SHA1Provider *>(ptr)->update ((unsigned char *)c_data, length_data);
    env->ReleaseByteArrayElements (j_data, c_data, 0);
  }

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    doFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_SHA1Provider_doFinal (JNIEnv *env, jobject jobj, jlong ptr)
  {
    unsigned char out[SHA1Provider::DIGEST_LENGTH];
    const char *error = reinterpret_cast<SHA1Provider *>(ptr)->doFinal (out);
    if (error)
      {
        throwException (env, error);
        return NULL;
      }
    jbyteArray j_result = env->NewByteArray (SHA1Provider::DIGEST_LENGTH);
    env->SetByteArrayRegion (j_result, 0, SHA1Provider::DIGEST_LENGTH, (jbyte *)out);
    return j_result;
  }

