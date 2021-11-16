namespace TestSignature
{
    public interface IVerification 
    {
        byte[] CreateSignatureForData(byte[] data);
        bool VerifyData(byte[] data, byte[] signature);
        string CreateSignatureForFile(string path);
    }
}