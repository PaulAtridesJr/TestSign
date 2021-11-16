using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TestSignature
{
    public class OpenSSLCertificateHelper : IVerification
    {
        /*
            генерим пару ключей
            openssl genrsa -out kt.pem 2048

            экспортим публичный ключ? зачем?
            openssl rsa -in kt.pem -outform PEM -pubout -out kt_pub.pem

            генерим X509 сертификат из пары ключей
            openssl req -x509 -key kt.pem -out kt_cert.pem -days 365 -nodes -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Contoso/OU=Security/CN=mypurpose.contoso.org"

            конвертим сертификат в PFX (пароль пустой)
            openssl pkcs12 -in kt_cert.pem -inkey kt.pem -export -clcerts -out kt_combined2.pfx -passout pass:

            потом установил уже kt_combined2.pfx в виндовый сторадж с пустым паролем. 
            И оттуда импортнул, как обычно, публичный ключ. Сертификат из стораджа удалил. 
        */
        private string OpenSSLBinFolder = "";// @"c:\Program Files\OpenSSL-Win64\bin";
        private readonly string _privateCertificatePath;
        private readonly string _publicCertificatePath;
        private readonly string _OpenSSLFolder;
        X509Certificate2 _publicKey = null;

        public OpenSSLCertificateHelper(string privateCertificatePath, string publicCertificatePath, string OpenSSLFolder) 
        {
            _privateCertificatePath = privateCertificatePath;
            _publicCertificatePath = publicCertificatePath;
            _OpenSSLFolder = OpenSSLFolder;

            if(String.IsNullOrEmpty(_OpenSSLFolder) == false && Directory.Exists(_OpenSSLFolder)) 
            {
                OpenSSLBinFolder = _OpenSSLFolder;
            }

            _publicKey = IOHelper.GetCertificateFromFile(_publicCertificatePath);
            if(_publicKey == null) 
            {
                Console.WriteLine("Faield to get public key");
            }
            else
            {
                Console.WriteLine("Public key loaded");
            }
        }

        byte[] IVerification.CreateSignatureForData(byte[] data)
        {
            throw new NotImplementedException();
        }

        string IVerification.CreateSignatureForFile(string path)
        {      
            string result = null;
            string signatureFileName = "sign.sha256";
            string signatureFilePath = "";
            string base64filepath = "";

            try
            {       
                var dir = Path.GetDirectoryName(path);
                if(String.IsNullOrEmpty(dir)) 
                {
                    signatureFilePath = Path.Combine(Path.GetTempPath(), signatureFileName);
                }
                else
                {
                    signatureFilePath = Path.Combine(dir, signatureFileName);
                }

                if(File.Exists(signatureFilePath)) 
                {
                    File.Delete(signatureFilePath);
                }

                // openssl dgst -sha256 -sign private.key -out sign.sha256 Metadata.inf
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.FileName = Path.Combine(OpenSSLBinFolder, "openssl.exe");
                psi.Arguments = $"dgst -sha256 -sign {_privateCertificatePath} -out {signatureFilePath} {path}";
                psi.RedirectStandardOutput = true;
                string eOut = null;
                psi.RedirectStandardError = true;
      
                Process p = new Process();
                p.StartInfo = psi;
                p.ErrorDataReceived += (s, a) => eOut += a.Data; 
                p.Start();
                
                p.BeginErrorReadLine();
                Console.WriteLine("OpenSSL: " + p.StandardOutput.ReadToEnd());
                p.WaitForExit();
                if(String.IsNullOrEmpty(eOut) == false) 
                {
                    Console.WriteLine("ERR: " + eOut);
                }

                bool signatureCreated = false;

                if(File.Exists(signatureFilePath) && 
                    new FileInfo(signatureFilePath).Length > 0) 
                {
                    Console.WriteLine($"Signed by OpenSSL and saved as '{signatureFilePath}'");
                    signatureCreated = true;
                }
                else
                {
                    Console.WriteLine("Failed to sign with OpenSSL");
                }

                if(signatureCreated == true) 
                {
                    // openssl enc -base64 -in sign.sha256 -out sign.sha256.base64
                    base64filepath = $"{signatureFilePath}.base64";

                    if(File.Exists(base64filepath)) 
                    {
                        File.Delete(base64filepath);
                    }

                    psi = new ProcessStartInfo();
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.FileName = Path.Combine(OpenSSLBinFolder, "openssl.exe");
                    psi.Arguments = $"enc -base64 -in {signatureFilePath} -out {base64filepath}";
                    psi.RedirectStandardOutput = true;
                    eOut = null;
                    psi.RedirectStandardError = true;
        
                    p = new Process();
                    p.StartInfo = psi;
                    p.ErrorDataReceived += (s, a) => eOut += a.Data; 
                    p.Start();
                    
                    p.BeginErrorReadLine();
                    Console.WriteLine("OpenSSL: " + p.StandardOutput.ReadToEnd());
                    p.WaitForExit();
                    if(String.IsNullOrEmpty(eOut) == false) 
                    {
                        Console.WriteLine("ERR: " + eOut);
                    }

                    if(File.Exists(base64filepath) && 
                        new FileInfo(base64filepath).Length > 0) 
                    {
                        Console.WriteLine($"Signature converted to Base64 and saved as '{base64filepath}'");

                        var s = File.ReadAllBytes(base64filepath);                      
                        var s2 = Encoding.ASCII.GetString(s);
                        s2 = s2.Replace(Environment.NewLine, "");
                        result = s2;
                    }
                    else
                    {
                        Console.WriteLine("Failed to convert signature with OpenSSL");
                    }
                }
            }
            catch (System.Exception ex)
            {                
                Console.WriteLine($"Failed to run openssl for signing - {ex.Message}");
            }
            finally 
            {
                if(File.Exists(signatureFilePath)) 
                {
                    File.Delete(signatureFilePath);
                }

                if(File.Exists(base64filepath)) 
                {
                    File.Delete(base64filepath);
                }
            }

            return result;
        }

        bool IVerification.VerifyData(byte[] data, byte[] signature)
        {
            bool verified = false;

            // openssl dgst -sha256 -verify public.pem -signature sign.sha256 Metadata.inf

            if(_publicKey != null) 
            {
                try
                {         
                    var csp = (RSACryptoServiceProvider)_publicKey.PublicKey.Key;       
                    verified = csp.VerifyData(data, SHA256.Create(), signature);
                }
                catch (CryptographicException e)
                {                
                    Console.WriteLine($"Failed to verify - {e.Message}");                
                } 
            }
            return verified;
        }
    }
}