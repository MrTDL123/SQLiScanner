using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DataSchema
{
    public record AiContextRequestPayload(
        string Url,
        string PageTitle,
        string CssPath,
        string HtmlBefore,
        string HtmlAfter);
}