using AngleSharp.Dom;
using AngleSharp.Html.Dom;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SQLiScanner.Utilities
{
    public static class DomSanitizer
    {
        public static void CleanReflectedNodes(IHtmlDocument document, string injectedPayload)
        {
            if (document == null || string.IsNullOrEmpty(injectedPayload)) return;

            string urlEncoded = HttpUtility.UrlEncode(injectedPayload);
            string aggressiveEncoded = ReflectionDetector.AggressiveUrlEncode(injectedPayload);

            // Duyệt qua content Text của các Node trước
            var textNodes = document.CreateTreeWalker(document.Body!, AngleSharp.Dom.FilterSettings.Text);
            INode currentNode;
            while ((currentNode = textNodes.ToNext()) != null)
            {
                ReadOnlySpan<char> nodeTextSpan = currentNode.TextContent.AsSpan();
                ReadOnlySpan<char> payloadSpan = injectedPayload.AsSpan();

                if (nodeTextSpan.IndexOf(payloadSpan, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var parentElement = currentNode.ParentElement;

                    if (parentElement != null &&
                        !parentElement.LocalName.Equals("body", StringComparison.OrdinalIgnoreCase) &&
                        !parentElement.LocalName.Equals("html", StringComparison.OrdinalIgnoreCase))
                    {
                        // Xóa node chứa nội dung rò rỉ XSS
                        parentElement.Remove();
                    }
                }
            }

            // Duyệt nội dung thuộc tính của tất cả thẻ 
            var elementsWithAttributes = document.QuerySelectorAll("*");
            foreach (var element in elementsWithAttributes)
            {
                foreach (var attr in element.Attributes.ToList())
                {
                    if (attr.Value.Contains(injectedPayload, StringComparison.OrdinalIgnoreCase) ||
                        attr.Value.Contains(urlEncoded, StringComparison.OrdinalIgnoreCase) ||
                        attr.Value.Contains(aggressiveEncoded, StringComparison.OrdinalIgnoreCase))
                    {
                        element.RemoveAttribute(attr.Name);
                    }
                }
            }
        }
    }
}
