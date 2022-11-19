using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Serilog.Core;

namespace HTTPS.Cert.Exporter;

internal class HttpClientHelper
{
    private readonly Logger _logger;

    public HttpClientHelper(Logger logger)
    {
        _logger = logger;
    }

    public bool ServerCertificateCustomValidationCallback(
        HttpRequestMessage httpsMessage,
        X509Certificate2? x509Certificate2,
        X509Chain? x509Chain,
        SslPolicyErrors sslPolicyErrors)
    {
        var httpsUrl = httpsMessage.RequestUri?.ToString() ?? string.Empty;

        // dump httpsRequest and all SSL certificate information
        _logger.Debug("httpsRequest JSON dump: {@httpsMessage}", httpsMessage);
        _logger.Debug("x509Certificate2 JSON dump: {@x509Certificate2}", x509Certificate2);
        _logger.Debug("x509Chain JSON dump: {@x509Chain}", x509Chain);
        _logger.Debug("sslPolicyErrors JSON dump: {@sslPolicyErrors}", sslPolicyErrors);

        // if Exported-HTTPS-SSL-Certificates Directory does not exist, create it.
        var requestExportedCertificatesFolderName =
            $".\\{Constants.ExportedCertificatesFolderName}\\{httpsUrl[Constants.Eight..].Replace(Constants.Slash, string.Empty)}";
        if (!Directory.Exists(requestExportedCertificatesFolderName))
        {
            Directory.CreateDirectory(requestExportedCertificatesFolderName);
            Console.WriteLine(
                $"[{Constants.ProgramName}]> CREATED Exported-HTTPS-SSL-Certificates DIRECTORY FOR EXPORTED CERTIFICATES");
            _logger.Warning("created {0} directory", Constants.ExportedCertificatesFolderName);
        }


        try
        {
            // create x509CertificateChain using certificate file formats
            // https://www.ibm.com/docs/en/sia?topic=osdc-certificate-key-formats-23
            var x509CertificateChain = string.Empty;
            if (x509Chain != null)
            {
                // exporting entire chain of certificates...
                Console.WriteLine($"[{Constants.ProgramName}]> EXPORTING ENTIRE CHAIN OF CERTIFICATES...");
                _logger.Information("exporting x509CertificateChain...");

                foreach (var x509Certificate in x509Chain.ChainElements)
                {
                    _logger.Debug("x509Certificate2 JSON dump: {@x509Certificate2}", x509Certificate2);
                    _logger.Information("got x509Certificate2 for: {0}",
                        x509Certificate.Certificate.GetNameInfo(X509NameType.SimpleName, true));

                    // export the certificate bytes, convert to base64, then format
                    var x509CertificateBytes = x509Certificate.Certificate.Export(X509ContentType.Cert);
                    var x509CertificateBase64 =
                        Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                    var x509CertificateFormatted =
                        $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}\n";
                    x509CertificateChain += x509CertificateFormatted;

                    _logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateFormatted);
                }

                // write certificate chain to a JSON file
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateChainJson = JsonConvert.SerializeObject(x509Chain);
                var x509CertificateChainJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                if (!File.Exists(x509CertificateChainJsonFilePath))
                {
                    File.WriteAllText(x509CertificateChainJsonFilePath, x509CertificateChainJson);
                    _logger.Information("wrote x509CertificateChainJson to: {0}", x509CertificateChainJsonFilePath);
                }
                else
                {
                    Console.WriteLine(
                        $"[{Constants.ProgramName}]> EXACT CERTIFICATE ALREADY EXPORTED, NOT EXPORTING AGAIN");
                    _logger.Information("exact x509CertificateChainJson already exists, not writing again");
                }
            }
            else if (x509Certificate2 != null)
            {
                // exporting one certificate...
                Console.WriteLine($"[{Constants.ProgramName}]> EXPORTING CERTIFICATE...");
                _logger.Information("exporting x509Certificate2...");
                _logger.Information("got x509Certificate2 for: {0}",
                    x509Certificate2.GetNameInfo(X509NameType.SimpleName, true));

                var x509CertificateBytes = x509Certificate2.Export(X509ContentType.Cert);
                var x509CertificateBase64 =
                    Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                x509CertificateChain =
                    $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}\n";

                _logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateChain);

                // write certificate to a JSON file
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateJson = JsonConvert.SerializeObject(x509Certificate2);
                var x509CertificateJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                if (!File.Exists(x509CertificateJsonFilePath))
                {
                    File.WriteAllText(x509CertificateJsonFilePath, x509CertificateJson);
                    _logger.Information("wrote x509CertificateJson to: {0}", x509CertificateJsonFilePath);
                }
                else
                {
                    Console.WriteLine(
                        $"[{Constants.ProgramName}]> EXACT CERTIFICATE ALREADY EXPORTED, NOT EXPORTING AGAIN");
                    _logger.Information("exact x509CertificateChainJson already exists, not writing again");
                }
            }

            // write x509CertificateChain to file
            var x509CertificateChainHash = HashHelper.Sha512Hash(x509CertificateChain);
            var x509CertificateChainFilePath =
                $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHash}.crt";

            if (!File.Exists(x509CertificateChainFilePath))
            {
                File.WriteAllText(x509CertificateChainFilePath, x509CertificateChain);
                _logger.Information("wrote x509CertificateChain to: {0}", x509CertificateChainFilePath);

                Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE TO FILE");
                Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE INFORMATION TO JSON FILE");

                // built it Windows X509Certificate2UI (WINDOWS ONLY)
                // https://stackoverflow.com/questions/15270764/get-ssl-certificate-in-net
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    new Thread(() =>
                        {
                            _logger.Information("showing certificate in Windows X509Certificate2UI");
                            Console.WriteLine(
                                $"[{Constants.ProgramName}]> SHOWING CERTIFICATE IN WINDOWS X509Certificate2UI...");

                            // check for Windows again to suppress warning...
                            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                X509Certificate2UI.DisplayCertificate(
                                    new X509Certificate2(x509CertificateChainFilePath));
                        }
                    ).Start();
            }
            else
            {
                _logger.Information("exact x509CertificateChainFilePath already exists, not writing again");
            }

            // allow HTTPS Response if no SslPolicyErrors
            return sslPolicyErrors == SslPolicyErrors.None;
        }
        catch (Exception ex)
        {
            // something went wrong, log it
            var exGuid = Guid.NewGuid();
            Console.WriteLine(
                $"[{Constants.ProgramName}]> SOMETHING WENT WRONG: [Exception GUID: {exGuid}]: {ex.Message}");
            _logger.Error(ex, "something went wrong: [{0}]", exGuid);
            return false;
        }
    }
}