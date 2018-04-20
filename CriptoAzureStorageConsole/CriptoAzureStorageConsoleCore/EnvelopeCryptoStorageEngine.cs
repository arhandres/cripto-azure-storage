using Microsoft.Azure.KeyVault.Core;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CriptoAzureStorageConsoleCore
{
    public class EnvelopeCryptoStorageEngine
    {
        private const string ENCRIPTION_INFO = "mycripto";

        private IKeyResolver _keyResolver = null;
        private CloudBlobClient _cloudBlobClient = null;

        public EnvelopeCryptoStorageEngine(CloudStorageAccount storageAccount, IKeyResolver keyResolver)
        {
            _keyResolver = keyResolver;
            _cloudBlobClient = storageAccount.CreateCloudBlobClient();
        }

        #region Storage

        public async Task<bool> UploadBlob(UploadBlobInfo uploadInfo)
        {
            var container = await GetContainer(uploadInfo.ContainerName);

            var blob = container.GetBlockBlobReference(uploadInfo.BlobPath);

            byte[] content = uploadInfo.Content;

            if (uploadInfo.IsEcrypted)
            {   
                var encryptedContent = await this.EncriptEvelopeData(uploadInfo.KeyIdentifier, uploadInfo.Content);

                content = encryptedContent.Item1;

                blob.Metadata.Add(encryptedContent.Item2);
            }

            using (var ms = new MemoryStream(content))
            {
                await blob.UploadFromStreamAsync(ms);
            }

            return true;
        }

        public async Task<byte[]> DownloadBlob(string containerName, string blobPath)
        {
            var container = await this.GetContainer(containerName);
            var blob = container.GetBlockBlobReference(blobPath);

            await blob.FetchAttributesAsync();

            var isEcrypted = blob.Metadata.ContainsKey(ENCRIPTION_INFO);

            byte[] content = null;

            using (var ms = new MemoryStream())
            {
                await blob.DownloadToStreamAsync(ms);
                content = ms.ToArray();
            }

            if (isEcrypted)
            {   
                content = await this.DecriptEnvelopeData(content, blob.Metadata);
            }

            return content;
        }

        private async Task<CloudBlobContainer> GetContainer(string containerName, bool makeItPublic = false)
        {
            CloudBlobContainer container = _cloudBlobClient.GetContainerReference(containerName);

            var exists = await container.ExistsAsync();
            if (!exists)
                await container.CreateAsync();

            if (makeItPublic)
            {
                var permission = await container.GetPermissionsAsync();
                permission.PublicAccess = BlobContainerPublicAccessType.Container;

                await container.SetPermissionsAsync(permission);
            }

            return container;
        }

        #endregion

        #region Envelope Encryption

        public async Task<Tuple<byte[], KeyValuePair<string, string>>> EncriptEvelopeData(string secretIdentifier, byte[] cleanData)
        {
            var key = await _keyResolver.ResolveKeyAsync(secretIdentifier, CancellationToken.None);

            if (key == null)
                throw new NullReferenceException("key");

            var envelope = this.InternalEnvelopeEncription(key, cleanData);

            var serializedEvelope = JsonConvert.SerializeObject(envelope);
            var keyValuePair = new KeyValuePair<string, string>(ENCRIPTION_INFO, serializedEvelope);

            return new Tuple<byte[], KeyValuePair<string, string>>(envelope.EncriptedData, keyValuePair);
        }

        private EnvelopeEncripted InternalEnvelopeEncription(IKey jwk, byte[] content)
        {
            var envelope = CreateEnvelopeEncripted(jwk);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, envelope.CryptoTransform, CryptoStreamMode.Write))
                {
                    cs.Write(content, 0, content.Length);
                }

                envelope.EncriptedData = ms.ToArray();
            }

            return envelope;
        }

        private EnvelopeEncripted CreateEnvelopeEncripted(IKey jwk)
        {
            using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
            {
                provider.Mode = CipherMode.CBC;
                provider.Padding = PaddingMode.PKCS7;

                var encriptedKey = jwk.WrapKeyAsync(provider.Key, null, CancellationToken.None).Result; 

                return new EnvelopeEncripted()
                {
                    KeyId = jwk.Kid,
                    SymetricKey = provider.Key,
                    SymetricKeyEcripted = encriptedKey.Item1,
                    IV = provider.IV,
                    CryptoTransform = provider.CreateEncryptor(),
                    Mode = provider.Mode,
                    Padding = provider.Padding,
                    Algorithm = encriptedKey.Item2
                };
            }
        }

        #endregion

        #region Envelope Decryption

        public async Task<byte[]> DecriptEnvelopeData(byte[] cryptoData, IDictionary<string, string> metadata)
        {
            if (metadata == null)
                throw new NullReferenceException(nameof(metadata));

            string metadataValue = null;
            if (!metadata.TryGetValue(ENCRIPTION_INFO, out metadataValue))
                throw new InvalidOperationException("No contiene valor en metadatos para " + ENCRIPTION_INFO);

            var envelope = await this.InternalEnvelopeDecription(cryptoData, metadataValue);

            return envelope.Data;
        }

        private async Task<EnvelopeEncripted> InternalEnvelopeDecription(byte[] content, string metadata)
        {
            var envelope = await CreateEnvelopeEncriptedForDecription(metadata);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, envelope.CryptoTransform, CryptoStreamMode.Write))
                {
                    cs.Write(content, 0, content.Length);
                }

                envelope.Data = ms.ToArray();
            }

            return envelope;
        }

        private async Task<EnvelopeEncripted> CreateEnvelopeEncriptedForDecription(string metadata)
        {
            var envelope = JsonConvert.DeserializeObject<EnvelopeEncripted>(metadata);

            var key = await _keyResolver.ResolveKeyAsync(envelope.KeyId, CancellationToken.None);

            using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
            {
                provider.Mode = envelope.Mode;
                provider.Padding = envelope.Padding;

                envelope.SymetricKey = key.UnwrapKeyAsync(envelope.SymetricKeyEcripted, null, CancellationToken.None).Result;

                provider.Key = envelope.SymetricKey;
                provider.IV = envelope.IV;

                envelope.CryptoTransform = provider.CreateDecryptor();
            }

            return envelope;
        }

        #endregion
    }
}
