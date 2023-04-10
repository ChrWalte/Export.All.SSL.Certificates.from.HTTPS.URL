# HTTPS-Cert-Exporter

HTTPS-Cert-Exporter takes in HTTPS urls and downloads the SSL certificates from them in the certificate file format and in a JSON file format. The system will log important information to a log file and will open the Windows Certificate Viewer if on a Windows machine.

## running

Running the HTTPS-Cert-Exporter is simple, just run the executable directly:

```bash
HTTPS-Cert-Exporter.exe
```

Optionally, you can pass in a list of HTTPS urls to get processed in the system:

```bash
HTTPS-Cert-Exporter.exe https://duckduckgo.com
```

## certificates

The downloaded certificates are placed in the /Exported-HTTPS-SSL-Certificates/ directory and are stored in a directory named the same as the HTTPS url, like:

```bash
/Exported-HTTPS-SSL-Certificates/duckduckgo.com/
```

Each certificate is downloaded as a certificate file and a json file, named by the hash of the certificate, like:

```bash
/Exported-HTTPS-SSL-Certificates/duckduckgo.com/19ec32ad6e.crt
/Exported-HTTPS-SSL-Certificates/duckduckgo.com/19ec32ad6e.crt.json
```

## logging

The HTTPS-Cert-Exporter dumps a lot of information into the log file. All the certificate information is dumped into the log file with exactly what steps were executes and when. The log file will also contain issues that the system comes across when attempting to download the certificates.
