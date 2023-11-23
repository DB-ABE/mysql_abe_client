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
#include <sstream>
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

	//用于测试签名验证：
	string db_sk_path = base_dir + "prikey/db.pem";
	string kms_sk_path = base_dir + "prikey/kms.pem";
	//用于测试解密
	string rsa_cert_path = base_dir + "certs/testabe@%cert.pem";
	string test_abe_key_path = base_dir + "abe/test_abe_key";
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

/*save key的测试放在了最后*/

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

// RSA加密，用于测试密钥保存功能
std::string my_RSA_Encrypt(const std::string strPemFileName, const std::string strData)
{
    // 打开rsa密钥文件
    FILE *hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        return "";
    }

    std::string strRet; // 存储加密结果
    // 从证书读取rsa密钥
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    RSA *pRSAPublicKey = EVP_PKEY_get1_RSA(evp_key);
    
    // 获取rsa长度
    int nLen = RSA_size(pRSAPublicKey);
    // 创建pencode临时存储加密密文
    char *pEncode = new char[nLen + 1];

    // 加密开始，分组进行加密
    if (strData.length() < RSA_Encrypt_length + 1)
    { // 如果长度小于一个分组
        int ret = RSA_public_encrypt(strData.length(), (const unsigned char *)strData.c_str(),
                                     (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            strRet = std::string(pEncode, ret);
        }
        else
        {
            strRet = "";
        }
    }
    else
    { // 如果长度大于一个分组
        int flag = 1;
        for (int i = 0; i < (int)strData.length() / RSA_Encrypt_length; i++)
        {                                                                                  // 每次处理一个分组,循环读取RSA_Encrypt_length长度分组进行加密
            std::string Data = strData.substr(i * RSA_Encrypt_length, RSA_Encrypt_length); // 一个分组
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                         (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += std::string(pEncode, ret);
            }
            else
            { // 加密失败，密文重置为""，跳出循环
                strRet = "";
                flag = 0;
                break;
            }
        }

        if (strData.length() % RSA_Encrypt_length != 0 && flag)
        { // 最后一段不够一个分组的情况, 前面的分组均正常
            std::string Data = strData.substr((strData.length() / RSA_Encrypt_length) * RSA_Encrypt_length,
                                              strData.length() % RSA_Encrypt_length); // 最后一段
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                         (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += std::string(pEncode, ret);
            }
            else
            { // 加密失败, 密文重置为"";
                strRet = "";
            }
        }
    }
    // 释放资源
    delete[] pEncode;
    EVP_PKEY_free(evp_key);
    X509_free(cert);
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

TEST_F(cryptoTest, cryptoSaveUserKey){
	std::stringstream buffer("y\nn\n");	//重定向输入，一行测试一次，
    std::streambuf * old = std::cin.rdbuf(buffer.rdbuf());
    
	abe_crypto crypto("testabe@%");
	bool res = crypto.import_sk(rsa_sk_path);
	EXPECT_EQ(true, res);
	if(res){
		std::string msg_raw = "test";//假设这是密钥
		std::string data_cipher = my_RSA_Encrypt(rsa_cert_path, msg_raw);
		if(data_cipher != ""){
			size_t msg_len = data_cipher.length();
			unsigned char * msg_b64 = (unsigned char*)malloc(base64_utils::b64_enc_len(msg_len));
			size_t msg_b64_length = base64_utils::b64_encode(data_cipher.c_str(), msg_len, (char*)msg_b64);
			string msg_b64_str((char*)msg_b64, msg_b64_length);


			bool res2 = crypto.import_user_key(test_abe_key_path);
			EXPECT_EQ(true, res2);
			res2 = crypto.save_user_key(test_abe_key_path, msg_b64_str);//用户输入y
			EXPECT_EQ(true, res2);
			res2 = crypto.save_user_key(test_abe_key_path, msg_b64_str);//用户输入n
			EXPECT_EQ(false, res2);

			//测试解密失败的情形
			res2 = crypto.import_sk(db_sk_path);
			EXPECT_EQ(true, res2);
			res2 = crypto.save_user_key(test_abe_key_path, msg_b64_str);//解密密钥和加密密钥不匹配
			EXPECT_EQ(false, res2);
		}
	}
	std::cin.rdbuf(old);
}