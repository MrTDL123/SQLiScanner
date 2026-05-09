using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using SQLiScanner.Models.Enums;

namespace SQLiScanner.Models
{
    // Được thiết kế Thread Safe khi đối tượng này sẽ được nhiều luồng tương tác cùng lúc
    public class PayloadState
    {
        public string TargetUrl { get; }
        public string ParamName { get; }
        public string Payload { get; }
        private int _status;
        public string ResultReason {get; private set;} = string.Empty;
        public PayloadState(string targetUrl, string paramName,string payload)
        {
            TargetUrl = targetUrl;
            ParamName = paramName;
            Payload = payload;
            _status = (int)ScanStatus.Pending;
        }

        public ScanStatus Status
        {
            get => (ScanStatus)Volatile.Read(ref _status);
        }

        public void UpdateStatus(ScanStatus newStatus, string reason = "")
        {
            Interlocked.Exchange(ref _status, (int)newStatus);

            if (!string.IsNullOrEmpty(reason))
            {
                ResultReason = reason;
            }
        }
    }
}