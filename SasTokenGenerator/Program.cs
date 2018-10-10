using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace SasTokenGenerator
{
    class Program
    {
        public static void Main()
        {
            Console.WriteLine(GenerateToken("MY_URL", "RootManageSharedAccessKey", "MY_SAS_KEY"));
            Console.ReadLine();
        }

        public static string GenerateToken(string resourceUri, string sasKeyName, string sasKey)
        {
            //set the token lifespan 
            TimeSpan sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var expiry = Convert.ToString((int) sinceEpoch.TotalSeconds + 3600); //1hour

            string stringToSign = HttpUtility.UrlEncode(resourceUri) + "\n" + expiry;
            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sasKey));
            var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

            //format the sas token 
            var sasToken = String.Format(CultureInfo.InvariantCulture,
                "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}",
                HttpUtility.UrlEncode(resourceUri), HttpUtility.UrlEncode(signature), expiry, sasKeyName);

            return sasToken;
        }
    }
}