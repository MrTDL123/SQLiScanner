using HtmlAgilityPack;

namespace SQLiScanner.Utility
{
    public class PrintHtmlHelper
    {
        public static void PrintCleanHtml(string rawHtml)
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(rawHtml);

            Console.WriteLine("--Nội dung phản hồi (Text Only)--");
            string textOnly = HtmlEntity.DeEntitize(doc.DocumentNode.InnerText);

            string[] lines = textOnly.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                if (!string.IsNullOrWhiteSpace(line))
                    Console.WriteLine(line.Trim());
            }
        }
    }
}
