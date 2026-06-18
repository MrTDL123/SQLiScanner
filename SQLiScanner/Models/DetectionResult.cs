using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models.Enums;

namespace SQLiScanner.Models
{
    public class DetectionResult
    {
        public string VulnerableURL { get; set; }
        public string VulnerableParam { get; set; }
        public string HttpMethod { get; set; }
        public string FoundContext { get; set; }
        public DatabaseType DatabaseType { get; set; } = DatabaseType.Unknow;
        public string WorkingPrefix { get; set; }
        public string WorkingSuffix { get; set; }
        public string ErrorMessage { get; set; }
        public bool IsExploitable { get; set; } = false;

        public bool IsCookieBypass { get; set; } = false;
        public bool IsReflected { get; set; } = false;

        public bool IsVulnerable => DatabaseType != DatabaseType.Unknow || 
                    (FoundContext != null && FoundContext.Equals("XSS", StringComparison.OrdinalIgnoreCase));
        public override string ToString()
        {
            if (FoundContext != null && FoundContext.Equals("XSS", StringComparison.OrdinalIgnoreCase))
            {
                return $"[XSS] Param: {VulnerableParam} | URL: {VulnerableURL}";
            }

            string bypassTag = IsCookieBypass ? "[COOKIE-BYPASS]" : "";
            return $"{bypassTag}[{DatabaseType}] Param:{VulnerableParam} Prefix:'{WorkingPrefix}' Suffix:'{WorkingSuffix}'";
        }
    }
}