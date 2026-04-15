using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models.Enums;

namespace SQLiScanner.Models
{
    public class DetectionResult
    {
        public bool IsExpointable { get; set; } = false;
        public string VulnerableURL { get; set; }
        public string FoundContext { get; set; }
        public DatabaseType DatabaseType { get; set; } = DatabaseType.Unknow;
        public string VulnerableParam { get; set; }
        public string WorkingPrefix { get; set; }
        public string WorkingSuffix { get; set; }
        public string ErrorMessage { get; set; }

        public bool IsVulnerable => DatabaseType != DatabaseType.Unknow;
        public override string ToString()
        {
            return $"[{DatabaseType}] Param:{VulnerableParam} Prefix:'{WorkingPrefix}' Suffix:'{WorkingSuffix}'";
        }
    }
}