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
