using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Utilities
{
    public static class ReflectionDetector
    {
        public static string GenerateCanaryToken()
        {
            return $"sqli{Random.Shared.Next(100000, 999999)}";
        }

        public static bool IsPayloadReflected(string responseBody, string payload)
        {
            if (string.IsNullOrEmpty(responseBody) || string.IsNullOrEmpty(payload))
                return false;
            
            ReadOnlySpan<char> bodySpan = responseBody.AsSpan();
            ReadOnlySpan<char> payloadSpan = payload.AsSpan();

            return bodySpan.IndexOf(payloadSpan, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static string RemovePayloadFromText(string originalText, string payload)
        {
            if (string.IsNullOrEmpty(originalText) || string.IsNullOrEmpty(payload))
                return originalText;

            string result = originalText;

            result = result.Replace(payload, string.Empty, StringComparison.OrdinalIgnoreCase);

            string urlEncodedPlus = System.Web.HttpUtility.UrlEncode(payload);
            if (!string.IsNullOrEmpty(urlEncodedPlus))
            {
                result = result.Replace(urlEncodedPlus, string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            string urlEncodedPercent = Uri.EscapeDataString(payload);
            if (!string.IsNullOrEmpty(urlEncodedPercent))
            {
                result = result.Replace(urlEncodedPercent, string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            string htmlEncoded = System.Net.WebUtility.HtmlEncode(payload);
            if (!string.IsNullOrEmpty(htmlEncoded))
            {
                result = result.Replace(htmlEncoded, string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            string aggressiveEncode = AggressiveUrlEncode(payload);
            if (!string.IsNullOrEmpty(aggressiveEncode))
            {
                result = result.Replace(aggressiveEncode, string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            return result; 
        }

        // Dành cho các web ASP.Net đời cũ, khi nội dung đều bị encode toàn bộ
        public static string AggressiveUrlEncode(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;

            var stringBuilder = new StringBuilder(value.Length * 3);
            foreach (char c in value) 
            {
                if (char.IsLetterOrDigit(c))
                {
                    // Văn bản hoặc số không bị encode
                    stringBuilder.Append(c);
                }
                else if (c == ' ')
                {
                    stringBuilder.Append('+');
                }
                else
                {
                    // Ép kiểu về Hex viết hoa 
                    stringBuilder.Append($"%{(int)c:X2}");
                }
            }
            return stringBuilder.ToString();
        }
    }
}
