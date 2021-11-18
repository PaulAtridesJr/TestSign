using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TestSignature
{
    public class WinCertificateHelper : IVerification
    {
        private readonly string _certificateSerial;
        private readonly StoreLocation _storeLocation;
        private readonly string _publicKeyPath;

        X509Certificate2 _privateKey = null;
        X509Certificate2 _publicKey = null;

        public WinCertificateHelper(string certificateSerial, StoreLocation storeLocation, string publicKeyPath) 
        {
            _certificateSerial = certificateSerial;
            _storeLocation = storeLocation;
            _publicKeyPath = publicKeyPath;

            _privateKey = GetCertificateFromStore(_certificateSerial, _storeLocation);
            if(_privateKey == null) 
            {
                Console.WriteLine("Failed to get private key");
            }
            else
            {
                Console.WriteLine("Private key loaded");
            }

            _publicKey = IOHelper.GetCertificateFromFile(_publicKeyPath);
            if(_publicKey == null) 
            {
                Console.WriteLine("Failed to get public key");
            }
            else
            {
                Console.WriteLine("Public key loaded");
            }
        }

        byte[] IVerification.CreateSignatureForData(byte[] data)
        {
            if(_privateKey == null) return null;

            try
            {
                var csp = (RSACryptoServiceProvider)_privateKey.PrivateKey;
                Console.WriteLine($"ProviderName : {csp.CspKeyContainerInfo.ProviderName}");
                Console.WriteLine($"ProviderType : {csp.CspKeyContainerInfo.ProviderType}");
                return csp.SignData(data, SHA512.Create()); 
            }
            catch (CryptographicException e)
            {                
                 Console.WriteLine($"Failed to sign - {e.Message}");
                 return null;
            } 
        }

        bool IVerification.VerifyData(byte[] data, byte[] signature)
        {
            if(_publicKey == null) return false;
            try
            {         
                var csp = (RSACryptoServiceProvider)_publicKey.PublicKey.Key;       
                return csp.VerifyData(data, SHA512.Create(), signature);
            }
            catch (CryptographicException e)
            {                
                 Console.WriteLine($"Failed to verify - {e.Message}");
                 return false;
            } 
        }

        private X509Certificate2 GetCertificateFromStore(string certificateSerial, StoreLocation storeLocation)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySerialNumber, certificateSerial, false);
                if (signingCert.Count == 0) 
                {
                    Console.WriteLine($"No certificates with serial '{certificateSerial}' were found in Store '{storeLocation}'");
                    return null;
                }
                    
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }

        string IVerification.CreateSignatureForFile(string path)
        {
            byte[] source = null;
            try
            {
                 source = File.ReadAllBytes(path);
            }
            catch (System.Exception ex)
            {
                Console.WriteLine($"Failed to read file to sign ('{path}') - {ex.Message}");
                return null;
            }
           
            var signature = (this as IVerification).CreateSignatureForData(source);
            return Convert.ToBase64String(signature);
        }
    }
}

