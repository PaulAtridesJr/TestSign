using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace TestSign2
{
    class Program
    {
        const string fileNameToSign = @"d:\Work\TestSign2\Metadata.inf";
        const string CertificateSerial = "270b8a22000200002475";
        const string ExportedCertificatePath = @"d:\Work\TestSign2\TestDataSign.cer";
        const string SignatureElementName = "Signature";

        static void Main(string[] args)
        {
            try 
            {
                X509Certificate2 certificateFromStore = GetCertificateFromStore(CertificateSerial);

                if(certificateFromStore != null) {
                    Console.WriteLine("Certificate from store asquired");
                }

                X509Certificate2 certificateFromRaw = new X509Certificate2();
                certificateFromRaw.Import(ReadFile(ExportedCertificatePath));

                if(certificateFromRaw != null) {
                    Console.WriteLine("Certificate from file asquired");
                }

                if (certificateFromStore != null && certificateFromRaw != null)
                {                   
                    // Note that this will return a Basic crypto provider, with only SHA-1 support
                    var privateKey = (RSACryptoServiceProvider)certificateFromStore.PrivateKey;
                    // Force use of the Enhanced RSA and AES Cryptographic Provider with openssl-generated SHA256 keys
                    //var enhCsp = new RSACryptoServiceProvider().CspKeyContainerInfo;
                    //var cspparams = new CspParameters(enhCsp.ProviderType, enhCsp.ProviderName, privateKey.CspKeyContainerInfo.KeyContainerName);
                    //privateKey = new RSACryptoServiceProvider(cspparams);
                    Console.WriteLine("Private key asquired");

                    var publicKey = (RSACryptoServiceProvider)certificateFromRaw.PublicKey.Key;
                    Console.WriteLine("Public key asquired");

                    byte[] data = File.ReadAllBytes(fileNameToSign); 
                    byte[] signature = null;
                    var source_xml = LoadXML(fileNameToSign);
                    if(source_xml != null)
                    {
                        var signature_element = source_xml.Root.Element(SignatureElementName);
                        if(signature_element != null) 
                        {   
                            if(String.IsNullOrEmpty(signature_element.Value) == false) 
                            {
                                try
                                {
                                    signature = Convert.FromBase64String(signature_element.Value);
                                }
                                catch (System.Exception ex)
                                {
                                    Console.WriteLine($"Signature is invalid - {ex.Message}");                                    
                                }                                
                            }
                            else
                            {
                                Console.WriteLine("Signature element is empty");
                            }
                            signature_element.Remove();
                        }

                        data = Encoding.UTF8.GetBytes(source_xml.ToString());
                    }  
                    Console.WriteLine("Source xml received");        

                    if(signature == null) 
                    {
                        Console.WriteLine($"File is unsigned. Adding signature ...");
                        signature = SignXML(data, privateKey);
                        Console.WriteLine("Source xml signed");   
                        source_xml.Root.Add(new XElement(SignatureElementName, Convert.ToBase64String(signature)));
                        SaveXML(source_xml, fileNameToSign);
                    }
                    else
                    {
                         // check data modified
                        //data[0] += 0x01;
                        Console.WriteLine("Signature found in xml. Verifying ...");                               
                        bool verified = VerifyXML(data, signature, publicKey);
                        Console.WriteLine($"Verification result: {verified}");
                    }                    
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Ex: {ex}");
            }
            Console.ReadLine();
        }

        private static byte[] SignXML(byte[] data, System.Security.Cryptography.RSACryptoServiceProvider csp)
        {         
            //return csp.SignData(data, System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA1"));
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAalg.ImportParameters(csp.ExportParameters(true));
                return RSAalg.SignData(data, SHA256.Create());  
            }
            catch (CryptographicException e)
            {                
                 Console.WriteLine($"Failed to sign - {e.Message}");
                 return null;
            } 
        }

        private static bool VerifyXML(byte[] data, byte[] signature, System.Security.Cryptography.RSACryptoServiceProvider csp)
        {                     
           // return csp.VerifyData(data, CryptoConfig.MapNameToOID("SHA1"), signature);         
            try
            {                
                return csp.VerifyData(data, SHA256.Create(), signature);
            }
            catch (CryptographicException e)
            {                
                 Console.WriteLine($"Failed to verify - {e.Message}");
                 return false;
            } 
        }

        internal static byte[] ReadFile (string fileName)
        {
            using(FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                int size = (int)f.Length;
                byte[] data = new byte[size];
                size = f.Read(data, 0, size);            
                return data;
            }
        }

        internal static XDocument LoadXML(string path)
        {
            try
            {
                XDocument doc = new XDocument();
                doc = XDocument.Load(path);
                return doc;
            }
            catch (System.Exception ex)
            {
                Console.WriteLine($"Failed to load xml - {ex.Message}");
                return null;
            }          
        }

        internal static bool SaveXML(XDocument document, string path)
        {
            try
            {
                document.Save(path);
                return true;
            }
            catch (System.Exception ex)
            {
                Console.WriteLine($"Failed to save xml - {ex.Message}");
                return false;
            }          
        }

        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySerialNumber, certName, false);
                if (signingCert.Count == 0)
                    return null;
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }

    }
}
