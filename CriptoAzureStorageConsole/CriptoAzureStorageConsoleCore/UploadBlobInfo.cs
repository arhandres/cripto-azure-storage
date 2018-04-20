using System;
using System.Collections.Generic;
using System.Text;

namespace CriptoAzureStorageConsoleCore
{
    public  class UploadBlobInfo
    {
        public string ContainerName { get; set; }

        public string BlobPath { get; set; }

        public string KeyIdentifier { get; set; }

        public bool IsEcrypted { get; set; }

        public byte[] Content { get; set; }
    }
}
