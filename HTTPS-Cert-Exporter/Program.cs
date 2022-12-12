using HTTPS.Cert.Exporter;
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
    var httpClientHelper = new HttpClientHelper(logger);
    using var httpsClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = httpClientHelper.ServerCertificateCustomValidationCallback,
        UseDefaultCredentials = true
    };

    // initialize HttpClient using httpsClientHandler
    using var httpsClient = new HttpClient(httpsClientHandler);
    logger.Debug("initialize HttpClient using httpsClientHandler");
    foreach (var httpsUrl in httpsUrls)
        try
        {
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
            Console.WriteLine(
                $"[{Constants.ProgramName}]> SOMETHING WENT WRONG: [Exception GUID: {exGuid}]: {ex.Message}");
            logger.Fatal(ex, "something went wrong: [{0}]", exGuid);
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

// keep console window open until enter is press
Console.ReadLine();