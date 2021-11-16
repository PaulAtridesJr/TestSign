using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TestSignature
{
    public static class IOHelper
    {        
        public static byte[] ReadFile (string fileName)
        {
            using(FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                int size = (int)f.Length;
                byte[] data = new byte[size];
                size = f.Read(data, 0, size);            
                return data;
            }
        }

        public static X509Certificate2 GetCertificateFromFile(string fileName) 
        {
            X509Certificate2 result = null;
            try
            {
                result = new X509Certificate2();               
                var raw = IOHelper.ReadFile(fileName);
                //var t = Encoding.Default.GetString(raw);   
                //t = t.Replace("-----BEGIN PUBLIC KEY-----", "");  
                //t = t.Replace("-----END PUBLIC KEY-----", "");  
                //t = t.Replace("\n", "");    
                //var raw2 = Convert.FromBase64String(t);

                result.Import(raw);                
            }
            catch (System.Exception ex)
            {
                Console.WriteLine($"Failed to load certificate from file '{fileName}' - {ex.Message}");                
            }

            return result;
        }
    }
}