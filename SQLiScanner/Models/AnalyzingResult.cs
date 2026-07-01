using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models.Enums;

namespace SQLiScanner.Models
{
    public class AnalyzingResult
    {
        public InjectionRoute Route { get; set; } = new InjectionRoute();
        public VulnerabilityType VulnTypes { get; set; } = VulnerabilityType.None;
        public string VulnerableParam => Route.TargetKey;
        public string VulnerableURL { get; set; }
        public string HttpMethod { get; set; }
        public DatabaseType DatabaseType { get; set; } = DatabaseType.Unknow;
        public string WorkingPrefix { get; set; }
        public string WorkingSuffix { get; set; }
        public string ErrorMessage { get; set; }

        public bool IsCookieBypass => Route.Type == RouteType.Cookie;
        public bool IsVulnerable => VulnTypes != VulnerabilityType.None;
        public bool IsXSS => VulnTypes.HasFlag(VulnerabilityType.XSS);
        public bool IsErrorExploitable => VulnTypes.HasFlag(VulnerabilityType.ErrorBased);
        public bool IsUnionExploitable => VulnTypes.HasFlag(VulnerabilityType.UnionBased);
        public bool IsTimeBased => VulnTypes.HasFlag(VulnerabilityType.TimeBasedBlind);
        public bool IsAbleToUnionExploit => VulnTypes != VulnerabilityType.TimeBasedBlind;

        public int ColumnCount { get; set; } = 0;
        public int EchoColumnIndex { get; set; } = -1;

        public int BaseResponseLength { get; set; } = 0;
        public double BooleanFalseThreshold { get; set; } = 0.0;
        public int DelayTime { get; set; } = 0;
        public override string ToString()
        {
            if (IsXSS)
            {
                return $"[XSS] Param: {VulnerableParam} | URL: {VulnerableURL}";
            }

            string bypassTag = IsCookieBypass ? "[COOKIE-BYPASS]" : "";
            return $"{bypassTag}[{DatabaseType}] Param:{VulnerableParam} Prefix:'{WorkingPrefix}' Suffix:'{WorkingSuffix}'";
        }
    }
}