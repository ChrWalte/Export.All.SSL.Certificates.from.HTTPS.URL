using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using HTTPS.Cert.Exporter;
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
    // get httpsUrls...
    var httpsUrls = new List<string>();
    logger.Information("getting httpsUrl(s)...");
    if (Environment.GetCommandLineArgs().Length >= Constants.Two)
    {
        // ...from Passed in Command Line Arguments

        // Environment.GetCommandLineArgs()[0] == program call == export.certs.from.https.exe
        foreach (var arg in Environment.GetCommandLineArgs()[Constants.One..])
        {
            httpsUrls.Add(arg.Trim().ToLowerInvariant());
            logger.Information("got httpsUrls from Environment.GetCommandLineArgs: {@httpsUrls}", httpsUrls);
        }
    }
    else
    {
        // ...from User Input

        Console.Write($"[{Constants.ProgramName}]> SPACE-SEPARATED HTTPS URL(s): ");
        var userInput = Console.ReadLine()?.Trim();

        if (string.IsNullOrWhiteSpace(userInput))
            userInput = Constants.DefaultHttpsUrl;

        foreach (var givenHttpUrl in userInput.Split(" "))
            httpsUrls.Add(givenHttpUrl.Trim().ToLowerInvariant());

        logger.Information("got httpsUrl(s) from Console.ReadLine(): {@httpsUrls}", httpsUrls);
    }

    // ensure httpsUrls are using httpsProtocol...
    logger.Information("checking given httpsUrls are using httpsProtocol...");
    for (var i = 0; i < httpsUrls.Count; i++)
    {
        logger.Information("checking given httpsUrl is using httpsProtocol: {0}", httpsUrls[i]);

        if (httpsUrls[i].Length > Constants.Eight && httpsUrls[i][..Constants.Eight] == Constants.HttpsProtocol)
        {
            // ...done.
            logger.Information("given httpsUrl is using httpsProtocol");
        }
        else if (httpsUrls[i].Length > Constants.Seven && httpsUrls[i][..Constants.Seven] == Constants.HttpProtocol)
        {
            // ...httpsUrl is using httpProtocol, ask for a httpsProtocol URL.
            logger.Warning(
                "given httpsUrl is not using httpsProtocol, it is using httpProtocol. asking for another httpsUrl...");

            Console.WriteLine(
                $"[{Constants.ProgramName}]> A HTTP URL WAS GIVEN ({httpsUrls[i]}), SSL CERTIFICATES DO NOT EXIST ON THIS PROTOCOL");
            Console.Write($"[{Constants.ProgramName}]> PLEASE ENTER A VALID URL USING THE HTTPS PROTOCOL: ");
            httpsUrls[i] = Console.ReadLine()?.Trim() ?? Constants.DefaultHttpsUrl;
            httpsUrls[i] = httpsUrls[i].ToLowerInvariant();

            // ensure httpsUrl is using httpsProtocol, or throw Exception
            if (httpsUrls[i][..Constants.Eight] != Constants.HttpsProtocol)
                throw new Exception(
                    $"httpsProtocol, {Constants.HttpsProtocol}, not found at the start of given httpsUrl: {httpsUrls[i][..Constants.Ten]}...");

            logger.Information("given httpsUrl is using httpsProtocol: {0}", httpsUrls[i]);
        }
        else
        {
            // ...append httpsProtocol to given httpsUrl
            httpsUrls[i] = $"{Constants.HttpsProtocol}{httpsUrls[i]}";
            logger.Information("appended httpsProtocol to given httpsUrl: {0}", httpsUrls[i]);
        }
    }

    // initialize httpsClientHandler to download certificates
    using var httpsClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (httpsMessage, x509Certificate2, x509Chain, sslPolicyErrors) =>
        {
            var httpsUrl = httpsMessage.RequestUri?.ToString() ?? string.Empty;

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
                    $"[{Constants.ProgramName}]> CREATED Exported-HTTPS-SSL-Certificates DIRECTORY FOR EXPORTED CERTIFICATES");
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
                    logger.Information("got x509Certificate2 for: {0}",
                        x509Certificate.Certificate.GetNameInfo(X509NameType.SimpleName, true));

                    // export the certificate bytes, convert to base64, then format
                    var x509CertificateBytes = x509Certificate.Certificate.Export(X509ContentType.Cert);
                    var x509CertificateBase64 =
                        Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                    var x509CertificateFormatted =
                        $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}\n";
                    x509CertificateChain += x509CertificateFormatted;

                    logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateFormatted);
                }

                // write certificate chain to a JSON file
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateChainJson = JsonConvert.SerializeObject(x509Chain);
                var x509CertificateChainJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                if (!File.Exists(x509CertificateChainJsonFilePath))
                {
                    File.WriteAllText(x509CertificateChainJsonFilePath, x509CertificateChainJson);
                    logger.Information("wrote x509CertificateChainJson to: {0}", x509CertificateChainJsonFilePath);
                }
                else
                {
                    Console.WriteLine(
                        $"[{Constants.ProgramName}]> EXACT CERTIFICATE ALREADY EXPORTED, NOT EXPORTING AGAIN");
                    logger.Information("exact x509CertificateChainJson already exists, not writing again");
                }
            }
            else if (x509Certificate2 != null)
            {
                // exporting one certificate...
                Console.WriteLine($"[{Constants.ProgramName}]> EXPORTING CERTIFICATE...");
                logger.Information("exporting x509Certificate2...");
                logger.Information("got x509Certificate2 for: {0}",
                    x509Certificate2.GetNameInfo(X509NameType.SimpleName, true));

                var x509CertificateBytes = x509Certificate2.Export(X509ContentType.Cert);
                var x509CertificateBase64 =
                    Convert.ToBase64String(x509CertificateBytes, Base64FormattingOptions.InsertLineBreaks);
                x509CertificateChain =
                    $"{Constants.CertificateFileHeader}\n{x509CertificateBase64}\n{Constants.CertificateFileFooter}\n";

                logger.Debug("x509Certificate2 base64 formatted:\n\n{0}\n", x509CertificateChain);

                // write certificate to a JSON file
                var x509CertificateChainHashForJsonFile = HashHelper.Sha512Hash(x509CertificateChain);
                var x509CertificateJson = JsonConvert.SerializeObject(x509Certificate2);
                var x509CertificateJsonFilePath =
                    $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHashForJsonFile}.crt.json";

                if (!File.Exists(x509CertificateJsonFilePath))
                {
                    File.WriteAllText(x509CertificateJsonFilePath, x509CertificateJson);
                    logger.Information("wrote x509CertificateJson to: {0}", x509CertificateJsonFilePath);
                }
                else
                {
                    Console.WriteLine(
                        $"[{Constants.ProgramName}]> EXACT CERTIFICATE ALREADY EXPORTED, NOT EXPORTING AGAIN");
                    logger.Information("exact x509CertificateChainJson already exists, not writing again");
                }
            }

            // write x509CertificateChain to file
            var x509CertificateChainHash = HashHelper.Sha512Hash(x509CertificateChain);
            var x509CertificateChainFilePath =
                $"{requestExportedCertificatesFolderName}\\{x509CertificateChainHash}.crt";

            if (!File.Exists(x509CertificateChainFilePath))
            {
                File.WriteAllText(x509CertificateChainFilePath, x509CertificateChain);
                logger.Information("wrote x509CertificateChain to: {0}", x509CertificateChainFilePath);

                Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE TO FILE");
                Console.WriteLine($"[{Constants.ProgramName}]> WROTE CERTIFICATE INFORMATION TO JSON FILE");

                // built it Windows X509Certificate2UI (WINDOWS ONLY)
                // https://stackoverflow.com/questions/15270764/get-ssl-certificate-in-net
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    new Thread(() =>
                        {
                            logger.Information("showing certificate in Windows X509Certificate2UI");
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
                logger.Information("exact x509CertificateChainFilePath already exists, not writing again");
            }

            // allow HTTPS Response if no SslPolicyErrors
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    };

    // initialize HttpClient using httpsClientHandler
    using var httpsClient = new HttpClient(httpsClientHandler);
    logger.Debug("initialize HttpClient using httpsClientHandler");
    foreach (var httpsUrl in httpsUrls)
    {
        // make a HTTPS GET Request to httpsUrl
        var httpsResponse = await httpsClient.GetAsync(httpsUrl);
        logger.Information("HTTPS GET {0}", httpsUrl[8..]);

        // ensure httpsResponse has Success Status Code
        httpsResponse.EnsureSuccessStatusCode();
        logger.Information("HTTPS GET Status Code: {0}", httpsResponse.StatusCode);
    }
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