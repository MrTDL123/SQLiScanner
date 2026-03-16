using SQLiScanner.Modules;
using SQLiScanner.Utility;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner
{
    class Program
    {
        static readonly HttpClient client = new HttpClient();
        static async Task Main(string[] args)
        {
            Console.WriteLine("==SQLi SCANNER DEMO 1.0==");
            Console.WriteLine("Nhập địa chỉ URL (VD: http://webbansach.com/chude?category=1): ");
            string url = Console.ReadLine();
            Console.Write("Nhập độ sâu cho việc quét website: ");
            string crawlDepthString = Console.ReadLine()?.Trim().ToLower() ?? "1";
            int maxDepth;

            if (crawlDepthString == "0" || crawlDepthString == "all" || crawlDepthString == "full")
            {
                // Gán bằng số lớn nhất của kiểu int (hơn 2 tỷ)
                // Coi như là vô hạn vì hiếm web nào sâu đến mức này
                maxDepth = int.MaxValue;
                Console.WriteLine("--> Chế độ: Quét KHÔNG GIỚI HẠN độ sâu.");
            }
            else
            {
                if (!int.TryParse(crawlDepthString, out maxDepth))
                {
                    maxDepth = 1;
                    Console.WriteLine("--> Input không hợp lệ, mặc định độ sâu = 1.");
                }
                else
                {
                    Console.WriteLine($"--> Chế độ: Giới hạn độ sâu {maxDepth}.");
                }
            }

            if (String.IsNullOrEmpty(url))
            {
                Console.WriteLine("Vui lòng nhập địa chỉ hợp lệ!");
                return;
            }

            Console.WriteLine($"[+] Đang kết nối đến {url}...");

            try
            {
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                HttpResponseMessage response = await client.GetAsync(url);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Kết nối thành công!");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Lỗi kết nối: {ex.Message}");
                Console.ResetColor();
            }
            //Bước 1: Crawl khắp response Html để tìm URL tiềm năng
            Crawler crawler = new Crawler(client);
            List<CrawlResult> targets = await crawler.CrawlAsync(url, maxDepth);
            if (targets.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Không tìm thấy URL tiềm năng để khai thác.");
                Console.ResetColor();
                return;
            }

            DatabaseDetector dbDetector = new DatabaseDetector(client);
            UnionDetector unionDetector = new UnionDetector(client);
            foreach (CrawlResult target in targets)
            {
                //Bước 2: Xác định hệ quản trị CSDL cùng với Prefix phù hợp.
                DetectionResult result = await dbDetector.DetectAsync(target);

                if (result.IsVulnerable)
                {
                    int colCount = await unionDetector.GetColumnCountAsync(target, result);
                    if (colCount > 0)
                    {
                        List<int> visibleCols = await unionDetector.GetVisibleColumnsAsync(target, result, colCount);
                        if (visibleCols.Count > 0)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n[***] EXPLOIT THÀNH CÔNG! BẠN CÓ THỂ KHAI THÁC DỮ LIỆU.");
                            Console.ResetColor();
                            // Sau này gọi hàm DumpData(target, detectResult, visibleCols[0]) ...
                        }
                    }

                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("    -> Clean.");
                    Console.ResetColor();
                }

            }


        }

        static async Task PrintResponseInfoAsync(HttpResponseMessage response)
        {
            int statusCode = (int)response.StatusCode;
            byte[] rawBytes = await response.Content.ReadAsByteArrayAsync();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[+] Nội dung response: ");
            Console.ResetColor();

            if (statusCode == 200) Console.ForegroundColor = ConsoleColor.Green;
            else Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine($"    Status Code: {statusCode} ({(System.Net.HttpStatusCode)statusCode})");
            Console.ResetColor();

            int bytesSize = rawBytes.Length;
            Console.WriteLine($"    Dung lượng:  {bytesSize} bytes");

            string html = Encoding.UTF8.GetString(rawBytes);
            //Lấy nội dung thẻ <title>
            var titleTag = "<title>";
            var titleStart = html.IndexOf(titleTag);

            if (titleStart >= 0)
            {
                titleStart += titleTag.Length;
                var titleEnd = html.IndexOf("</title>", titleStart);

                if (titleEnd > titleStart)
                {
                    string title = html.Substring(titleStart, titleEnd - titleStart);
                    Console.WriteLine($"    Tiêu đề:     {title}");
                }
                else
                {
                    Console.WriteLine($"    Tiêu đề:     [KHÔNG TÌM THẤY]");
                }
            }

            Console.WriteLine("    Nội dung response:");
            PrintHtmlHelper.PrintCleanHtml(html);
        }

    }


    #region Data Class
    public class DetectionResult
    {
        public DbType DatabaseType { get; set; } = DbType.Unknow;
        public string VulnerableParam { get; set; }
        public string WorkingPrefix { get; set; }
        public string WorkingSuffix { get; set; }
        public string ErrorMessage { get; set; }

        public bool IsVulnerable => DatabaseType != DbType.Unknow;
        public override string ToString()
        {
            return $"[{DatabaseType}] Param:{VulnerableParam} Prefix:'{WorkingPrefix}' Suffix:'{WorkingSuffix}'";
        }
    }

    public enum DbType
    {
        Unknow,
        MySQL,
        MSSQL, //Microsoft SQL server
        Oracle,
        PostgreSQL,
        SQLite
    }
    #endregion
}
