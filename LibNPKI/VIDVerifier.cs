using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;
using Org.BouncyCastle.Asn1;
using Mono.Security;
using Mono.Security.Cryptography;
using LibNPKI.Exceptions;

namespace LibNPKI
{
    public class VIDVerifier
    {
        public bool VerifyWithID(X509Certificate2 cert, PKCS8.PrivateKeyInfo priKey, string idn)
        {
            getVIDHash(cert, out string name, out string hashOid, out byte[] hash);
            Debug.WriteLine("Name : " + name);
            Debug.WriteLine("hashOid : " + hashOid);
            Debug.WriteLine("Hash : " + BitConverter.ToString(hash));
            byte[] randomNum = getRandomNum(priKey);
            Debug.WriteLine("RandomNum : " + BitConverter.ToString(randomNum));
            byte[] hash2 = generateVIDHash(randomNum, idn, hashOid);
            Debug.WriteLine("Hash2 : " + BitConverter.ToString(hash2));
            return Enumerable.SequenceEqual(hash, hash2);

        }
        private byte[] doubleHash(byte[] content, string oid)
        {
            // VID = h(h(VID, R));
            // get hash algorithm obj from oid
            string hashName = Oid.FromOidValue(oid, OidGroup.HashAlgorithm).FriendlyName;
            Debug.WriteLine("VID Hash Algorithm : " + hashName);
            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashName);
            // return hashed
            byte[] resultTmp = hashAlgorithm.ComputeHash(content);
            return hashAlgorithm.ComputeHash(resultTmp);

        }
        private byte[] generateVIDHash(byte[] randomNum, string idn, string oid)
        {
            // HashContent ::= SEQEUNCE {idn PrintableString, randomNum BIT_STRING }
            DerSequence sequence = new DerSequence(new DerPrintableString(idn), new DerBitString(randomNum));
            return doubleHash(sequence.GetDerEncoded(), oid);

        }
        private byte[] getRandomNum(PKCS8.PrivateKeyInfo priKey)
        {
            foreach(ASN1 i in priKey.Attributes)
            {
                Asn1Reader reader = new Asn1Reader(i.GetBytes());
                bool isRandomNumAttribute = false, inSET = false;
                do
                {
                    if (reader.TagName == "OBJECT_IDENTIFIER")
                    {
                        if (((Asn1ObjectIdentifier)reader.GetTagObject()).Value.Value == "1.2.410.200004.10.1.1.3")
                        {
                            isRandomNumAttribute = true;
                        }
                    }
                    else if (reader.TagName == "SET" && isRandomNumAttribute)
                    {
                        inSET = true;
                    }
                    else if (reader.TagName == "BIT_STRING" && inSET)
                    {
                        Asn1BitString asn1BitString = new Asn1BitString(reader);
                        return asn1BitString.Value;
                    }
                } while (reader.MoveNext());
            }
            throw new VIDOperationException("RandomNum in private key attributes is missing");
        }
        private void getVIDHash(X509Certificate2 cert, out string name, out string hashAlg, out byte[] hash)
        {
            // ignore warnings
            name = "";
            hashAlg = "";
            hash = new byte[] { };
            bool notset_n = true, notset_hal = true, notset_ha = true;
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid.Value != "2.5.29.17") continue;
                Asn1Reader reader = new Asn1Reader(ext.RawData);
                bool kisaIdentifyData = false, kisaVid = false; // TO-DO : Caluate Depth
                do
                {
                    switch (reader.TagName)
                    {
                        case "OBJECT_IDENTIFIER":
                            Asn1ObjectIdentifier identifier = (Asn1ObjectIdentifier)reader.GetTagObject();
                            string oid = identifier.Value.Value;
                            if (oid == "1.2.410.200004.10.1.1")
                                kisaIdentifyData = true;
                            else if (oid == "1.2.410.200004.10.1.1.1")
                                kisaVid = true;
                            else if (kisaVid && notset_hal)
                            {
                                hashAlg = oid;
                                notset_hal = false;
                            }
                            break;
                        case "UTF8String":
                            if (kisaIdentifyData && notset_n)
                            {
                                name = Encoding.UTF8.GetString(reader.GetPayload());
                                notset_n = false;
                            }
                            break;
                        case "OCTET_STRING":
                            if (kisaVid && notset_ha)
                            {
                                SysadminsLV.Asn1Parser.Universal.Asn1OctetString octetString = new SysadminsLV.Asn1Parser.Universal.Asn1OctetString(reader);
                                hash = octetString.Value;
                                notset_ha = false;
                            }
                            break;
                        default:
                            break;
                    }
                } while (reader.MoveNext());
                if (notset_ha || notset_hal || notset_n)
                {
                    throw new VIDOperationException("Some of vid informations in certificate are missing");
                }
            }
        }
    }
}
