using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
{
    public class CrawlResult
    {
        public string BaseUrl { get; set; }
        public string HttpMethod { get; set; }
        public bool IsForm { get; set; }
        public Dictionary<string, string> Params { get; set; } = new();
        public string OriginalCookie { get; set; } = string.Empty;
        public string RawQueryString { get; set; } = string.Empty;
        public double PageTolerance { get; set; } = 0.05;
        public string FullUrl
        {
            get
            {
                if (string.IsNullOrWhiteSpace(RawQueryString))
                    return BaseUrl;

                string separator = RawQueryString.StartsWith('?') ? "" : "?";
                return $"{BaseUrl}{separator}{RawQueryString}";
            }
        }
    }
}
