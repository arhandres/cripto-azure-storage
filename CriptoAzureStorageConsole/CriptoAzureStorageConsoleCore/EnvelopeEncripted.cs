using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CriptoAzureStorageConsoleCore
{
    public class EnvelopeEncripted
    {
        [JsonIgnore]
        public ICryptoTransform CryptoTransform { get; set; }

        [JsonIgnore]
        public byte[] Data { get; set; }

        [JsonIgnore]
        public byte[] EncriptedData { get; set; }

        [JsonIgnore]
        public byte[] SymetricKey { get; set; }

        public byte[] SymetricKeyEcripted { get; set; }

        public byte[] IV { get; set; }

        public string KeyId { get; set; }

        public string Algorithm { get; set; }

        public CipherMode Mode { get; set; }

        public PaddingMode Padding { get; set; }

        public string ModeDescription { get { return this.Mode.ToString(); } }

        public string PaddingDescription { get { return this.Padding.ToString(); } }
    }
}
