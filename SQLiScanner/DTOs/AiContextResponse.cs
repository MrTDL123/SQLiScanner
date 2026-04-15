using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SQLiScanner.DTOs
{
    public record AiContextResponse(
        bool IsVulnerable,
        string Reason
    );
}