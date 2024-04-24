using Microsoft.Web.Administration;
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using CommandLine.Text;

namespace Certbot2IIS
{
    internal class Program
    {
        public class Options
        {
            [Option('c', "certfile", Required = true, HelpText = "PEM certificate file")]
            public string CertFile { get; set; } = "";

            [Option('k', "keyfile", Required = true, HelpText = "PEM private key file")]
            public string KeyFile { get; set; } = "";

            [Option('n', "friendlyname", Required = true, HelpText = "Certificate friendly name")]
            public string FriendlyName { get; set; } = "";

            [Option('s', "sitename", Required = true, HelpText = "IIS site name")]
            public string SiteName { get; set; } = "";

            [Option('h', "hostname", Required = false, HelpText = "IIS site binding site name")]
            public string HostName { get; set; } = "";
        }

        static void Main(string[] args)
        {
            var parser = new Parser(with => with.HelpWriter = null);
            var parserResult = parser.ParseArguments<Options>(args);
            parserResult
              .WithParsed<Options>(options => RunOptions(options))
              .WithNotParsed(errs => DisplayHelp(parserResult));
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);

            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.Heading = "Certbot2IIS version " + fvi.FileVersion;
                h.Copyright = "Copyright 2023-2024 Brayns.it";
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        static void RunOptions(Options opts)
        {
            X509Certificate2 newCert = X509Certificate2.CreateFromPemFile(opts.CertFile, opts.KeyFile);
            newCert.FriendlyName = opts.FriendlyName;
            newCert = new X509Certificate2(newCert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            bool certExists = false;
            List<X509Certificate2> toRemove = new();
            foreach (var c in store.Certificates)
                if (c.FriendlyName.Equals(opts.FriendlyName, StringComparison.OrdinalIgnoreCase))
                    if (c.GetCertHashString() != newCert.GetCertHashString())
                        toRemove.Add(c);
                    else
                        certExists = true;

            foreach (var c in toRemove)
                store.Remove(c);

            if (!certExists)
                store.Add(newCert);

            store.Close();

            if (!SetSiteCertificate(opts.SiteName, opts.HostName, newCert))
                if (!SetSiteCertificate(opts.SiteName, opts.HostName, newCert))
                    throw new Exception("Unable to set certificate");
        }

        private static bool SetSiteCertificate(string siteName, string hostName, X509Certificate2 certificate)
        {
            try
            {
                bool doCommit = false;
                ServerManager serverManager = new ServerManager();

                foreach (var b in serverManager.Sites[siteName].Bindings)
                {
                    if (b.Protocol.ToLower() == "https")
                    {
                        if ((hostName.Length == 0) || b.Host.Equals(hostName, StringComparison.OrdinalIgnoreCase))
                        {
                            if ((b.CertificateHash == null) || (!b.CertificateHash.SequenceEqual(certificate.GetCertHash())))
                            {
                                b.CertificateStoreName = "My";
                                b.CertificateHash = certificate.GetCertHash();
                                b.BindingInformation = b.BindingInformation;    // force IIS to bind
                                doCommit = true;
                            }
                        }
                    }
                }

                if (doCommit)
                    serverManager.CommitChanges();

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}