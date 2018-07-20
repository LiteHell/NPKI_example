using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Mono.Security.Cryptography;
using LibNPKI.Exceptions;

namespace LibNPKI
{
    public class CertificateLoader
    {
        public static PKCS8.PrivateKeyInfo DecryptPrivateKey(CertificateLocation cert, string password)
        {
            var privateKey = cert.EncryptedPrivateKeyInfo;
            PasswordDeriveBytes pbkdf1 = new PasswordDeriveBytes(password, privateKey.Salt, "SHA1", privateKey.IterationCount);
            byte[] dk = pbkdf1.GetBytes(20);
            byte[] k = new byte[16];
            byte[] iv = new byte[16];
            Array.Copy(dk,0, k,0, 16);
            if (privateKey.Algorithm == "1.2.410.200004.1.4")
            {
                // 고정 IV값
                iv = new byte[] { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };
            }
            else if (privateKey.Algorithm == "1.2.410.200004.1.15")
            {
                byte[] hash = new byte[20];
                hash = SHA1.Create().ComputeHash(dk,16,4);
                Array.Copy(hash, 0, iv, 0, 16);
            } else
            {
                throw new NotSupportedAlgorithmException("Not supported algorithm for private key");
            }
            
            byte[] decrypted = seedDecrypt(privateKey.EncryptedData, k, iv);
            return new PKCS8.PrivateKeyInfo(decrypted);
        }

        public static RSA ConvertPrivateKeyToRSA(byte[] privateKey)
        {
            return PKCS8.PrivateKeyInfo.DecodeRSA(privateKey);
        }

        private static byte[] seedDecrypt(byte[] data, byte[] k, byte[] iv)
        {
            // https://stackoverflow.com/questions/29701401 참고
            // http://zest133.tistory.com/entry/%EB%8C%80%EC%B9%AD%ED%82%A4-%EC%95%94%ED%98%B8%ED%99%94-%EC%9D%B4%EC%95%BC%EA%B8%B01 참고
            CbcBlockCipher blockCipher = new CbcBlockCipher(new SeedEngine());
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());
            KeyParameter keyParam = new KeyParameter(k);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv);
            cipher.Reset();
            cipher.Init(false, keyParamWithIV);
            byte[] result = new byte[cipher.GetOutputSize(data.Length)];
            int length = cipher.ProcessBytes(data, result, 0); try
            {
                length += cipher.DoFinal(result, length);
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                throw new IncorretPasswordException();
            }
            return result;

        }
    }
}
