using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Export.All.SSL.Certificates.from.HTTPS.URL;
using Newtonsoft.Json;
using Serilog;

// initialize serilog logger
var logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .Enrich.FromLogContext()
    .WriteTo.File($".\\{Constants.ProgramName}.log", outputTemplate: Constants.SerilogOutputTemplate)
    .CreateLogger();
logger.Debug("initialized logger");

try
{
    // get httpsUrl...
    string httpsUrl;
    logger.Information("getting httpsUrl...");
    if (Environment.GetCommandLineArgs().Length == Constants.Two)
    {
        // ...from Passed in Command Line Arguments

        // Environment.GetCommandLineArgs()[0] == program call == export.certs.from.https.exe
        httpsUrl = Environment.GetCommandLineArgs()[Constants.One].ToLowerInvariant();
        logger.Information("got httpsUrl from Environment.GetCommandLineArgs: {0}", httpsUrl);
    }
    else
    {
        // ...from User Input

        Console.Write($"[{Constants.ProgramName}]> HTTPS URL: ");
        httpsUrl = Console.ReadLine()?.Trim().ToLowerInvariant() ?? Constants.DefaultHttpsUrl;
        if (string.IsNullOrWhiteSpace(httpsUrl))
            httpsUrl = Constants.DefaultHttpsUrl;

        logger.Information("got httpsUrl from Console.ReadLine(): {0}", httpsUrl);
    }

    // ensure httpsUrl is httpsProtocol...
    logger.Information("checking given httpsUrl is httpsProtocol...");
    if (httpsUrl[..Constants.Eight] == Constants.HttpsProtocol)
    {
        // ...done.

        logger.Information("given httpsUrl is httpsProtocol");
    }
    else if (httpsUrl[..Constants.Seven] == Constants.HttpProtocol)
    {
        // ...httpsUrl is httpProtocol, ask for a httpsProtocol URL.

        logger.Warning("given httpsUrl is not httpsProtocol, it is httpProtocol. asking for another httpsUrl...");

        Console.WriteLine($"[{Constants.ProgramName}]> HTTP URL GIVEN, SSL CERTIFICATES DO NOT EXIST ON THIS PROTOCOL");
        Console.Write($"[{Constants.ProgramName}]> PLEASE ENTER A VALID URL USING THE HTTPS PROTOCOL: ");
        httpsUrl = Console.ReadLine()?.Trim() ?? Constants.DefaultHttpsUrl;
        httpsUrl = httpsUrl.ToLowerInvariant();

        // ensure httpsUrl is httpsProtocol, or throw Exception
        if (httpsUrl[..Constants.Eight] != Constants.HttpsProtocol)
            throw new Exception(
                $"httpsProtocol, {Constants.HttpsProtocol}, not found at start of given httpsUrl: {httpsUrl[..Constants.Ten]}...");

        logger.Information("given httpsUrl is httpsProtocol: {0}", httpsUrl);
    }
    else
    {
        // ...append httpsProtocol to given httpsUrl

        httpsUrl = $"{Constants.HttpsProtocol}{httpsUrl}";
        logger.Information("appended httpsProtocol to given httpsUrl: {0}", httpsUrl);
    }

    // initialize httpsClientHandler to download certificates
    using var httpsClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (httpsMessage, x509Certificate2, x509Chain, sslPolicyErrors) =>
        {
            // dump httpsRequest and all SSL certificate information
            logger.Debug("httpsRequest JSON dump: {@httpsMessage}", httpsMessage);
            logger.Debug("x509Certificate2 JSON dump: {@x509Certificate2}", x509Certificate2);
            logger.Debug("x509Chain JSON dump: {@x509Chain}", x509Chain);
            logger.Debug("sslPolicyErrors JSON dump: {@sslPolicyErrors}", sslPolicyErrors);

            // if Exported-HTTPS-SSL-Certificates Directory does not exist, create it.
            var requestExportedCertificatesFolderName =
                $".\\{Constants.ExportedCertificatesFolderName}\\{httpsUrl[Constants.Eight..].Replace(Constants.Slash, string.Empty)}";
            if (!Directory.Exists(requestExportedCertificatesFolderName))
            {
                Directory.CreateDirectory(requestExportedCertificatesFolderName);
                Console.WriteLine(
                    $"[{Constants.ProgramName}]> CREATED Exported-HTTPS-SSL-Certificates DIRECTORY FOR Exported CERTIFICATES");
                logger.Warning("created {0} directory", Constants.ExportedCertificatesFolderName);
            }

            // create x509CertificateChain using certificate file formats
            // https://www.ibm.com/docs/en/sia?topic=osdc-certificate-key-formats-23
            var x509CertificateChain = string.Empty;
            if (x509Chain != null)
            {
                // exporting entire chain of certificates...
                Console.WriteLine($"[{Constants.ProgramName}]> EXPORTING ENTIRE CHAIN OF CERTIFICATES...");
                logger.Information("exporting x509CertificateChain...");

                foreach (var x509Certificate in x509Chain.ChainElements)
                {
                    logger.Debug("x509Certificate2 JSON dump: {@x509Certificate2}", x509Certificate2);
                    logger.Information("got x509Certificate2 for: {0}", x509Certificate.Certificate.FriendlyName);

                    // export the certificate bytes, convert to base64, then format
                    var x509CertificateBytes = x509Certificate.Certificate.Export(X509ContentType.Cert);
                    var x509CertificateBase64 =
                        Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                    var x509CertificateFormatted =
                        $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}";
                    x509CertificateChain += x509CertificateFormatted;

                    logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateFormatted);
                }

                // write certificate chain to a JSON file
                // TODO: async/await?
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateChainJson = JsonConvert.SerializeObject(x509Chain);
                var x509CertificateChainJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                // TODO: add full hash to file properties?
                File.WriteAllText(x509CertificateChainJsonFilePath, x509CertificateChainJson);
                logger.Information("wrote x509CertificateChainJson to: {0}", x509CertificateChainJsonFilePath);
            }
            else if (x509Certificate2 != null)
            {
                // exporting one certificate...
                Console.WriteLine($"[{Constants.ProgramName}]> EXPORTING CERTIFICATE...");
                logger.Information("exporting x509Certificate2...");
                logger.Information("got x509Certificate2 for: {0}", x509Certificate2.FriendlyName);

                var x509CertificateBytes = x509Certificate2.Export(X509ContentType.Cert);
                var x509CertificateBase64 =
                    Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                x509CertificateChain =
                    $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}";

                logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateChain);

                // write certificate to a JSON file
                // TODO: async/await?
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateJson = JsonConvert.SerializeObject(x509Certificate2);
                var x509CertificateJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                // TODO: add full hash to file properties?
                File.WriteAllText(x509CertificateJsonFilePath, x509CertificateChain);
                logger.Information("wrote x509CertificateJson to: {0}", x509CertificateJsonFilePath);
            }

            // write x509CertificateChain to file
            // TODO: async/await?
            var x509CertificateChainHash = HashHelper.Sha512Hash(x509CertificateChain);
            var x509CertificateChainFilePath =
                $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHash}.crt";

            // TODO: add full hash to file properties?
            File.WriteAllText(x509CertificateChainFilePath, x509CertificateChain);
            logger.Information("wrote x509CertificateChain to: {0}", x509CertificateChainFilePath);

            Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE TO FILE");
            Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE INFORMATION TO JSON FILE");

            // built it Windows X509Certificate2UI (WINDOWS ONLY)
            // https://stackoverflow.com/questions/15270764/get-ssl-certificate-in-net
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                logger.Information("showing certificate in Windows X509Certificate2UI");
                Console.WriteLine($"[{Constants.ProgramName}]> SHOWING CERTIFICATE IN WINDOWS X509Certificate2UI...");

                // thread out, no built in await :(
                X509Certificate2UI.DisplayCertificate(new X509Certificate2(x509CertificateChainFilePath));
            }

            // allow HTTPS Response if no SslPolicyErrors
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    };

    // initialize HttpClient using httpsClientHandler
    using var httpsClient = new HttpClient(httpsClientHandler);
    logger.Debug("initialize HttpClient using httpsClientHandler");

    // make a HTTPS GET Request to httpsUrl
    var httpsResponse = await httpsClient.GetAsync(httpsUrl);
    logger.Information("HTTPS GET {0}", httpsUrl[8..]);

    // ensure httpsResponse has Success Status Code
    httpsResponse.EnsureSuccessStatusCode();
    logger.Information("HTTPS GET Status Code: {0}", httpsResponse.StatusCode);
}
catch (Exception ex)
{
    // something went wrong, log it
    var exGuid = Guid.NewGuid();
    Console.WriteLine($"[{Constants.ProgramName}]> SOMETHING WENT WRONG: [Exception GUID: {exGuid}]: {ex.Message}");
    logger.Fatal(ex, "something went wrong: [{0}]", exGuid);
}

Console.WriteLine($"[{Constants.ProgramName}]> EXITED.\n");
logger.Information("exited.\n");