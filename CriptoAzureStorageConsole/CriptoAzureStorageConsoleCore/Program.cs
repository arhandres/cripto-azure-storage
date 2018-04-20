using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Storage;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CriptoAzureStorageConsoleCore
{
    class Program
    {
        static string _vaultUrl = "https://indexkeyvault.vault.azure.net";
        static string _clientId = "0ad5507e-11e7-4cf6-8c79-a570e8bb0b49";
        static string _clientSecret = "tEapdZQw14guzSa+43KS1LYnEGexZemLBiDghIp5K/c=";

        static string _blobContainer = "criptocontainer";
        static string _blobPath = "CryptoFile.txt";

        static Random _random = new Random((int)DateTime.Now.Ticks);

        static void Main(string[] args)
        {
            Run().Wait();
        }

        static async Task Run()
        {
            var size = (int)Math.Pow(1024, 3);//1 GB
            var data = CreateRandomData(size);

            var storageAccount = CloudStorageAccount.DevelopmentStorageAccount;
            var keyResolver = CreateKeyVaultKeyResolver();

            var envelopeHelper = new EnvelopeCryptoStorageEngine(storageAccount, keyResolver);

            var kid = await CreateMasterKey();

            var success = await envelopeHelper.UploadBlob(new UploadBlobInfo()
            {
                ContainerName = _blobContainer,
                BlobPath = _blobPath,
                Content = data,
                IsEcrypted = true,
                KeyIdentifier = kid
            });

            if (success)
            {
                var decryptedContent = await envelopeHelper.DownloadBlob(_blobContainer, _blobPath);

                var isByteEqual = ContentsAreEqualByte(data, decryptedContent);
                var isHashEqual = ContentAreEqualHash(data, decryptedContent);

                if (isByteEqual && isHashEqual)
                    Console.WriteLine("Same content");
            }

            Console.ReadKey();
        }

        static byte[] CreateRandomData(int size)
        {
            var buffer = new byte[size];

            _random.NextBytes(buffer);

            return buffer;
        }

        static bool ContentsAreEqualByte(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
                return false;

            using (var fs1 = new MemoryStream(first))
            {
                using (var fs2 = new MemoryStream(second))
                {
                    for (int i = 0; i < first.Length; i++)
                    {
                        if (fs1.ReadByte() != fs2.ReadByte())
                            return false;
                    }
                }
            }

            return true;
        }

        static bool ContentAreEqualHash(byte[] first, byte[] second)
        {
            byte[] firstHash = MD5.Create().ComputeHash(first);
            byte[] secondHash = MD5.Create().ComputeHash(second);

            for (int i = 0; i < firstHash.Length; i++)
            {
                if (firstHash[i] != secondHash[i])
                    return false;
            }

            return true;
        }

        private static KeyVaultClient CreateKeyValueClient()
        {
            var keyClient = new KeyVaultClient(async (authority, resource, scope) =>
            {
                var adCredential = new ClientCredential(_clientId, _clientSecret);
                var authenticationContext = new AuthenticationContext(authority, null);
                return (await authenticationContext.AcquireTokenAsync(resource, adCredential)).AccessToken;
            });

            return keyClient;
        }

        static KeyVaultKeyResolver CreateKeyVaultKeyResolver()
        {
            var keyVaultClient = CreateKeyValueClient();

            return new KeyVaultKeyResolver(keyVaultClient);
        }

        public static async Task<string> CreateMasterKey()
        {
            var keyType = "RSA";
            var keySize = 2048;

            var keyVaultClient = CreateKeyValueClient();

            var identifier = Guid.NewGuid().ToString();

            var bundle = await keyVaultClient.CreateKeyAsync(_vaultUrl, identifier, keyType, keySize);

            return bundle.KeyIdentifier.Identifier;
        }
    }
}
