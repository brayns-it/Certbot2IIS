using Microsoft.Web.Administration;
using System.Security.Cryptography.X509Certificates;
using CommandLine;

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
            Parser.Default.ParseArguments<Options>(args).WithParsed(RunOptions);
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

            bool doCommit = false;
            ServerManager serverManager = new ServerManager();
            foreach (var b in serverManager.Sites[opts.SiteName].Bindings)
            {
                if (b.Protocol.ToLower() == "https")
                {
                    if ((opts.HostName.Length == 0) || b.Host.Equals(opts.HostName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!b.CertificateHash.SequenceEqual(newCert.GetCertHash()))
                        {
                            b.CertificateStoreName = "My";
                            b.CertificateHash = newCert.GetCertHash();
                            doCommit = true;
                        }
                    }
                }
            }

            if (doCommit)
                serverManager.CommitChanges();
        }
    }
}