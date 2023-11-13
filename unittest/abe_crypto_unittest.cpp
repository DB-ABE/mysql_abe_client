#include "src/abe_crypto.h"
#include "src/my_utils/base64.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "gmock-global.h"
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"
#include <fstream>
#include <iostream>
#include <string>
using std::string;

class cryptoTest : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
    	std::cout<<"Init cryptoTest..."<<std::endl;
	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
	string base_dir = "./data/";
	string kms_cert_path = base_dir + "certs/kmscert.pem";
	string db_cert_path = base_dir + "certs/dbcert.pem";

	string rsa_sk_path = base_dir + "prikey/testabe@%.pem";

	string abe_key_path = base_dir + "abe/abe_key";
	string abe_pp_path = base_dir + "abe/abe_pp";

	//签名验证用：
	string db_sk_path = base_dir + "prikey/db.pem";
	string kms_sk_path = base_dir + "prikey/kms.pem";
};

TEST_F(cryptoTest, cryptoInitSuccess1){
	abe_crypto crypto("testabe@%");
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(true, res);//正常路径
}

TEST_F(cryptoTest, cryptoInitSuccess2){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, new_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(true, res);//abe_key导入失败，但程序逻辑上允许
}

TEST_F(cryptoTest, cryptoInitFail1){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(new_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//mpk导入失败
}

TEST_F(cryptoTest, cryptoInitFail3){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    new_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//kms_cert导入失败
}

TEST_F(cryptoTest, cryptoInitFail4){
	abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, new_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//db_cert导入失败
}

TEST_F(cryptoTest, cryptoInitFail5){
	abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    new_path);
    EXPECT_EQ(false, res);//rsa私钥导入失败
}

TEST_F(cryptoTest, cryptoSetName){
	abe_crypto crypto("testabe@%");
	crypto.set_name("test");
    EXPECT_EQ("test", crypto.user.user_id);
}

TEST_F(cryptoTest, cryptoSetAtt){
	abe_crypto crypto("testabe@%");
	crypto.set_att("test");
    EXPECT_EQ("test", crypto.user.user_attr);
}

TEST_F(cryptoTest, cryptoImportMpk){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_mpk(abe_pp_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_mpk(new_path);
    EXPECT_EQ(false, res);
}

TEST_F(cryptoTest, cryptoImportUserKey){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_user_key(abe_key_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_user_key(new_path);
    EXPECT_EQ(false, res);
}

TEST_F(cryptoTest, cryptoImportSaveKey){//todo
	
}

TEST_F(cryptoTest, cryptoCheckAbeKey){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.check_abe_key();
	EXPECT_EQ(false, res);
	crypto.user.user_key = "test";
	res = crypto.check_abe_key();
    EXPECT_EQ(true, res);
}

TEST_F(cryptoTest, cryptoImportDbCert){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_db_cert(db_cert_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_db_cert(new_path);
    EXPECT_EQ(false, res);

	res = crypto.import_db_cert(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
	//todo:后面两个return NULL路径怎么测？
}

TEST_F(cryptoTest, cryptoImportKmsCert){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_kms_cert(kms_cert_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_kms_cert(new_path);
    EXPECT_EQ(false, res);

	res = crypto.import_kms_cert(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
	//todo:后面两个return NULL路径怎么测？
}

TEST_F(cryptoTest, cryptoImportSk){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_sk(rsa_sk_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_sk(new_path);
    EXPECT_EQ(false, res);//文件不存在

	res = crypto.import_sk(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
}

TEST_F(cryptoTest, cryptoEncAndDec){
	abe_crypto crypto("testabe@%");
	crypto.set_name("test");
	bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
	if(res){
		string pt, ct;
		res = crypto.encrypt("hello", "attr1 and attr2",ct);
		EXPECT_EQ(true, res);
		res = crypto.decrypt(ct, pt);
		EXPECT_EQ(true, res);
		EXPECT_EQ("hello", pt);
	}
}

TEST_F(cryptoTest, cryptoDecFail){
	abe_crypto crypto("testabe@%");
	string pt, ct;
	ct = "test";
	bool res = crypto.decrypt(ct, pt);
	EXPECT_EQ(false, res);//没有abe_key
	res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
	if(res){
		res = crypto.encrypt("hello", "attr1 and attr3",ct);
		EXPECT_EQ(true, res);
		res = crypto.decrypt(ct, pt);
		EXPECT_EQ(true, res);//属性（attr1 | attr2）不符合策略
		EXPECT_EQ("can't decrypt.", pt);//解密失败返回值
	}
}

// 签名 use private key
bool my_RSA_Sign(const std::string strPemFileName, std::string strData,
             unsigned char *pEncode, unsigned int &outlen)
{
    // 读取rsa私钥文件，导入私钥
    FILE *hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        return false;
    }
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    {
		fclose(hPriKeyFile);
        return false;
    }
	fclose(hPriKeyFile);

    // 签名
    unsigned char digest[NID_sha512];
    SHA512((unsigned char *)strData.c_str(), strData.length(), digest);
    int ret = RSA_sign(NID_sha512, (const unsigned char *)digest, SHA512_DIGEST_LENGTH,
                       pEncode, &outlen, pRSAPriKey);
    // 释放资源
    RSA_free(pRSAPriKey);
    
    return ret == 1 ? true: false;
}

TEST_F(cryptoTest, cryptoVerifyDbSig){
	abe_crypto crypto("testabe@%");
	bool res = crypto.import_db_cert(db_cert_path);//验签需要证书

	EXPECT_EQ(true, res);
	string msg_raw = "hello";//原始信息
	unsigned char RSA_sign_buf[257];
	unsigned int sign_len;
	res = my_RSA_Sign(db_sk_path, msg_raw, RSA_sign_buf, sign_len);
	if(res){
		unsigned char * sig_b64 = (unsigned char*)malloc(base64_utils::b64_enc_len(sign_len));
		size_t sig_b64_length = base64_utils::b64_encode((char *)RSA_sign_buf, sign_len, (char*)sig_b64);
		string sig_b64_str((char*)sig_b64, sig_b64_length);
		bool res2 = crypto.verify_db_sig(msg_raw, sig_b64_str);
		EXPECT_EQ(res2, true);

		//使用错误的证书
		res2 = crypto.import_db_cert(kms_cert_path);//验签需要证书
		EXPECT_EQ(true, res2);
		res2 = crypto.verify_db_sig(msg_raw, sig_b64_str);
		EXPECT_EQ(false, res2);

		free(sig_b64);
	}else{
		std::cout << "生成测试用签名失败" << std::endl;
	}
}

TEST_F(cryptoTest, cryptoVerifyKmsSig){
	abe_crypto crypto("testabe@%");
	bool res = crypto.import_kms_cert(kms_cert_path);//验签需要证书

	EXPECT_EQ(true, res);
	string msg_raw = "hello";//原始信息
	size_t msg_len = msg_raw.length();
	unsigned char * msg_b64 = (unsigned char*)malloc(base64_utils::b64_enc_len(msg_len));
	size_t msg_b64_length = base64_utils::b64_encode(msg_raw.c_str(), msg_len, (char*)msg_b64);
	string msg_b64_str((char*)msg_b64, msg_b64_length);

	unsigned char RSA_sign_buf[257];
	unsigned int sign_len;
	res = my_RSA_Sign(kms_sk_path, msg_raw, RSA_sign_buf, sign_len);
	if(res){
		unsigned char * sig_b64 = (unsigned char*)malloc(base64_utils::b64_enc_len(sign_len));
		size_t sig_b64_length = base64_utils::b64_encode((char *)RSA_sign_buf, sign_len, (char*)sig_b64);
		string sig_b64_str((char*)sig_b64, sig_b64_length);
		

		bool res2 = crypto.verify_kms_sig(msg_b64_str, sig_b64_str);
		EXPECT_EQ(res2, true);

		//使用错误的证书
		res2 = crypto.import_kms_cert(db_cert_path);//验签需要证书
		EXPECT_EQ(true, res2);
		res2 = crypto.verify_kms_sig(msg_b64_str, sig_b64_str);
		EXPECT_EQ(false, res2);
		free(sig_b64);

	}else{
		std::cout << "生成测试用签名失败" << std::endl;
	}
	
	free(msg_b64);
}