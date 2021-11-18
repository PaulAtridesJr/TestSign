using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace TestSignature
{
    class Program
    {       
        const string SignatureElementName = "Signature";       
       
        static void Main(string[] args)
        {
            string OpenSSLPrivateKeyPath = "";
            string PublicKeyPath = "";
            string fileNameToSign = "";
            string OpenSSLFolder = "";
            bool UseOpenSSL = true;
            string CertificateSerial = "";
            try
            {
                 for(int i = 0; i< args.Length; i++) 
                 {
                     if(args[i].StartsWith("/ospriv=")) 
                     {
                        OpenSSLPrivateKeyPath = args[i].Substring("/ospriv=".Length);
                     }
                     else if (args[i].StartsWith("/pubkey="))
                     {
                        PublicKeyPath = args[i].Substring("/pubkey=".Length);
                     }
                     else if (args[i].StartsWith("/src="))
                     {
                        fileNameToSign = args[i].Substring("/src=".Length);
                     }
                     else if (args[i].StartsWith("/ospath="))
                     {
                        OpenSSLFolder = args[i].Substring("/ospath=".Length);
                     }
                     else if (args[i].StartsWith("/pfxserial="))
                     {
                        CertificateSerial =  args[i].Substring("/pfxserial=".Length);
                     }
                     else if (args[i].StartsWith("/pfx"))
                     {
                        UseOpenSSL = false;
                     }                    
                     else if (args[i].StartsWith("/hlp"))
                     {
                        Console.WriteLine($"Using OpenSSL by default{Environment.NewLine}" + 
                        $"/src=_path_ - file to sign{Environment.NewLine}" +
                        $"/pubkey=_path_ - exported public key (CER){Environment.NewLine}" + 
                        $"/pfx - Optional. Use certificate from storage without OpenSSL{Environment.NewLine}" +
                        $"/ospriv=_path_ - Optional (if OpenSSL). PEM/KEY private key for use with OpenSSL{Environment.NewLine}" + 
                        $"/pfxserial=_serial_ - Optional (if /pfx). Certificate in storage serial number{Environment.NewLine}" +                                                                     
                        $"/ospath=_folder_ - Optional (if openssl.exe not in PATH). Folder with OpenSSL binaries {Environment.NewLine}");
                        return;
                     }
                 }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine($"Failed to parse params - {ex.Message}");                
            }

            bool readyToStart = true;
            if(string.IsNullOrEmpty(fileNameToSign) == true || 
                File.Exists(fileNameToSign) == false) 
            {
                Console.WriteLine("Set source file with param '/src=_path_ to file'. /hlp - to help");
                readyToStart = false;
            }

            if(UseOpenSSL == true) 
            {
                if(String.IsNullOrEmpty(OpenSSLPrivateKeyPath) == false &&
                   File.Exists(OpenSSLPrivateKeyPath) == true &&
                   String.IsNullOrEmpty(PublicKeyPath) == false &&
                   File.Exists(PublicKeyPath) == true) 
                {
                    readyToStart = true;
                }   
                else
                {
                    Console.WriteLine("Define OpenSSL private key and public key. /hlp - to help");
                }             
            }
            else
            {
                if(String.IsNullOrEmpty(CertificateSerial) == false &&
                   File.Exists(PublicKeyPath) == true) 
                {
                    readyToStart = true;
                }   
                else
                {
                    Console.WriteLine("Define PFX serial and exported public key. /hlp - to help");
                }  
            }

            if(readyToStart == true)
            {    
                IVerification verification = null;            
                try 
                {
                    if(UseOpenSSL == true) 
                    {
                        verification = 
                            new OpenSSLCertificateHelper(
                                OpenSSLPrivateKeyPath,
                                PublicKeyPath,
                                OpenSSLFolder);
                    }
                    else
                    {
                        verification = 
                            new WinCertificateHelper(
                                CertificateSerial, 
                                StoreLocation.LocalMachine,
                                PublicKeyPath);
                    }
                                                  
                        string signature = null;
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
                                        signature = signature_element.Value;
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

                            source_xml.Save(fileNameToSign);
                        }  
                        Console.WriteLine("Source xml received");        

                        if(signature == null) 
                        {
                            Console.WriteLine($"File is unsigned. Adding signature ...");
                            signature = verification.CreateSignatureForFile(fileNameToSign);
                            if(signature != null) 
                            {
                                Console.WriteLine("Source xml signed");   
                                source_xml.Root.Add(new XElement(SignatureElementName, signature));
                                SaveXML(source_xml, fileNameToSign);

                                signature = null;
                                source_xml = LoadXML(fileNameToSign);
                                if(source_xml != null)
                                {
                                    var signature_element = source_xml.Root.Element(SignatureElementName);
                                    if(signature_element != null) 
                                    {   
                                        if(String.IsNullOrEmpty(signature_element.Value) == false) 
                                        {
                                            try
                                            {
                                                signature = signature_element.Value;
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

                                    source_xml.Save(fileNameToSign);
                                }  
                                Console.WriteLine("Source xml received");       

                                var data = File.ReadAllBytes(fileNameToSign);
                                Console.WriteLine("Signature found in xml. Verifying ...");                               
                                bool verified = verification.VerifyData(data, Convert.FromBase64String(signature));
                                Console.WriteLine($"Verification result: {verified}");
                            }
                        }
                        else
                        {
                            // check data modified
                            //data[0] += 0x01;
                            var data = File.ReadAllBytes(fileNameToSign);
                            Console.WriteLine("Signature found in xml. Verifying ...");                               
                            bool verified = verification.VerifyData(data, Convert.FromBase64String(signature));
                            Console.WriteLine($"Verification result: {verified}");
                        } 
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"Ex: {ex}");
                }
            }
            else
            {
                Console.WriteLine("Run with /hlp - to help");
            }
            Console.ReadLine();
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

    }
}
