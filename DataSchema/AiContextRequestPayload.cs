using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DataSchema
{
    public record AiContextRequestPayload(
        string TargetUrl,
        string PageTitle,
        string CssPath,
        string TrueUrl,
        string TrueHtml,
        string FalseUrl,
        string FalseHtml);
}