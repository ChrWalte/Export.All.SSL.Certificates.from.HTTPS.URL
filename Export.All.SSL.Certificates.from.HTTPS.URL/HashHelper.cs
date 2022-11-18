using System.Security.Cryptography;
using System.Text;

namespace Export.All.SSL.Certificates.from.HTTPS.URL;

internal class HashHelper
{
    public static string Sha512Hash(string input)
    {
        using var sha512 = SHA512.Create();

        var stringBuilder = new StringBuilder();
        var inputBytes = Encoding.ASCII.GetBytes(input);
        foreach (var b in sha512.ComputeHash(inputBytes))
            stringBuilder.Append(b.ToString("x2"));

        return stringBuilder.ToString()[..Constants.Ten];
    }
}