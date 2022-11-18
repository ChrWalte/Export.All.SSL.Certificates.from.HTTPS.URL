namespace Export.All.SSL.Certificates.from.HTTPS.URL;

internal class Constants
{
    public const string ProgramName = "Export.All.SSL.Certificates.from.HTTPS.URL";
    public const string ExportedCertificatesFolderName = "Exported-HTTPS-SSL-Certificates";
    public const string DefaultHttpsUrl = "https://duckduckgo.com/";

    public const string HttpsProtocol = "https://";
    public const string HttpProtocol = "http://";

    public const string Slash = "/";
    public const int One = 1;
    public const int Two = 2;
    public const int Seven = 7;
    public const int Eight = 8;
    public const int Ten = 10;

    public const string CertificateFileHeader = "-----BEGIN CERTIFICATE-----";
    public const string CertificateFileFooter = "-----END CERTIFICATE-----";

    public const string SerilogOutputTemplate = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level}] {Message}{NewLine}{Exception}";
}