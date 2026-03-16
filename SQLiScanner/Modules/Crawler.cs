using HtmlAgilityPack;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace SQLiScanner.Modules
{
    public class CrawlResult
    {
        
        public string FullUrl { get; set; }
        public string HttpMethod { get; set; }
        public bool IsForm { get; set; }
        public Dictionary<string, string> Params { get; set; }

        public CrawlResult() 
        {
            Params = new Dictionary<string, string>();
            
        }
    }

    public class Crawler
    {
        private readonly HttpClient _client;
        //Dùng để lọc các url có trùng cấu trúc
        private HashSet<string> _scannedSignatures = new HashSet<string>();
        // Lưu trữ các URL đã truy cập
        private HashSet<string> _visitedUrls = new HashSet<string>();
        public Crawler(HttpClient client)
        {
            _client = client;
        }
        public async Task<List<CrawlResult>> CrawlAsync(string rootUrl, int maxDepth)
        {
            _scannedSignatures.Clear();
            _visitedUrls.Clear();

            List<CrawlResult> results = new List<CrawlResult>();

            // Queue lưu trữ URL và độ sâu hiện tại của nó
            Queue<(string Url, int Depth)> urlQueue = new Queue<(string, int)>();
            urlQueue.Enqueue((rootUrl, 0));
            _visitedUrls.Add(rootUrl);

            while (urlQueue.Count > 0)
            {
                if (_visitedUrls.Count >= 10000)
                {
                    Console.WriteLine("Đã đạt giới hạn an toàn 10,000 trang. Dừng quét.");
                    return results;
                }


                var (currentUrl, currentDepth) = urlQueue.Dequeue();
                Console.WriteLine($"\n--- ĐỘ SÂU {currentDepth}: Kiểm tra URL khả thi trong [{currentUrl}] ---");

                try
                {
                    string html = await _client.GetStringAsync(currentUrl);
                    var doc = new HtmlDocument();
                    doc.LoadHtml(html);

                    ExtractForms(currentUrl, doc, results);

                    ExtractLinksAndQueue(rootUrl, currentUrl, doc, results, urlQueue, currentDepth, maxDepth);

                    await ExtractLinksFromScriptTags(rootUrl, currentUrl, doc, results);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] Lỗi Crawler: {ex.Message}");
                    Console.ResetColor();
                }
            }

            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] KẾT THÚC QUÁ TRÌNH THU THẬP: Thấy được {results.Count} điểm tấn công tiềm năng.");
            Console.ResetColor();
            return results;
        }

        private string GetUrlSignature(string fullUrl, string method, IEnumerable<string> paramNames)
        {
            try
            {
                // Lấy phần gốc (VD: http://site.com/news.php?id=1 -> http://site.com/news.php)
                Uri uri = new Uri(fullUrl);
                string basePath = uri.GetLeftPart(UriPartial.Path);

                // Lấy các tham số tồn tại trong url để đối chiếu, sắp xếp để không quan tâm thứ tự
                List<string> sortedParams = paramNames.OrderBy(p => p).ToList();
                string paramString = string.Join(",", sortedParams);

                return $"{method.ToUpper()}|{basePath}|{paramString}";
            }
            catch
            {
                return fullUrl;
            }
        }

        //LỌC TÌM THẺ <A>
        private void ExtractLinksAndQueue(
            string rootUrl,
            string currentUrl,
            HtmlDocument doc,
            List<CrawlResult> results,
            Queue<(string, int)> queue,
            int currentDepth,
            int maxDepth)
        {


            //tìm tất cả thẻ a có thuộc tính href
            var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
            if (linkNodes == null) return;

            foreach (var node in linkNodes)
            {
                string href = node.GetAttributeValue("href", "").Trim();

                if(href.Contains("AJAX") && currentDepth == 1)
                {
                    Console.WriteLine();
                }

                if (string.IsNullOrEmpty(href) || href.Contains("#") || href.StartsWith("javascript") || href.StartsWith("mailto")) 
                    continue;

                string? fullUrl = NormalizeUrl(rootUrl, currentUrl, href);

                if (fullUrl == null) continue;

                if(fullUrl.Contains("?"))
                {
                    //Kiểm tra trùng lặp cú pháp query
                    var uri = new Uri(fullUrl);
                    var queryParams = HttpUtility.ParseQueryString(uri.Query);
                    var paramNames = queryParams.AllKeys.Where(k => k != null).ToList();

                    if (paramNames.Count > 0)
                    {
                        string signature = GetUrlSignature(fullUrl, "GET", paramNames);

                        if (!_scannedSignatures.Contains(signature))
                        {
                            _scannedSignatures.Add(signature);
                            var paramsDict = new Dictionary<string, string>();
                            foreach (var key in paramNames) paramsDict[key] = queryParams[key];

                            results.Add(new CrawlResult
                            {
                                FullUrl = fullUrl,
                                HttpMethod = "GET",
                                IsForm = false,
                                Params = paramsDict
                            });
                        }
                    }
                }

                if (currentDepth < maxDepth)
                {
                    string baseUrlForCrawl = fullUrl.Split('?')[0];

                    if (!_visitedUrls.Contains(baseUrlForCrawl))
                    {
                        _visitedUrls.Add(baseUrlForCrawl);
                        queue.Enqueue((fullUrl, currentDepth + 1));
                        Console.WriteLine($"    [->] Queueing: {fullUrl}");
                    }
                }

            }
        }

        //LỌC TÌM THẺ <FORM>
        private void ExtractForms(string currentUrl, HtmlDocument doc, List<CrawlResult> results)
        {
            var formNodes = doc.DocumentNode.SelectNodes("//form");
            if (formNodes == null) return;
            foreach (var form in formNodes)
            {
                string action = form.GetAttributeValue("action", "").Trim();
                string method = form.GetAttributeValue("method", "GET").ToUpper();

                string? submitUrl = string.IsNullOrEmpty(action) ? currentUrl : NormalizeUrl(currentUrl, currentUrl, action);
                if (submitUrl is null) continue;

                // Tìm tất cả thẻ input, textarea, select trong form
                // .// nghĩa là tìm con cháu của node hiện tại
                var inputNodes = form.SelectNodes(".//input | .//textarea | .//select");
                var formParams = new Dictionary<string, string>();

                if(inputNodes != null)
                {
                    foreach(var input in inputNodes)
                    {
                        string name = input.GetAttributeValue("name", "");
                        string type = input.GetAttributeValue("type", "").ToLower();
                        string originalValue = input.GetAttributeValue("value", "");


                        if (!string.IsNullOrEmpty(name) && type != "submit" && type != "image"
                                                        && type != "reset" && type != "button")
                        {
                            if (!string.IsNullOrEmpty(originalValue) || type == "hidden")
                            {
                                formParams[name] = originalValue;
                            }
                            else
                            {
                                // Nếu là ô trống cho người dùng nhập -> Điền "TEST" để đánh dấu
                                formParams[name] = GuessInputValue(input, name, type);
                            }
                        }
                    }
                }

                if (formParams.Count > 0)
                {
                    string signature = GetUrlSignature(submitUrl, method, formParams.Keys);
                    if (!_scannedSignatures.Contains(signature))
                    {
                        _scannedSignatures.Add(signature);
                        string resultUrl = submitUrl;

                        if (method == "GET")
                        {
                            var queryList = formParams.Select(p => $"{p.Key}={p.Value}");
                            if (!resultUrl.Contains("?")) resultUrl += "?" + string.Join("&", queryList);
                            else resultUrl += "&" + string.Join("&", queryList);
                        }

                        results.Add(new CrawlResult
                        {
                            FullUrl = resultUrl,
                            HttpMethod = method,
                            IsForm = true,
                            Params = formParams
                        });

                        if (method == "GET")
                        {
                            Console.WriteLine($"    [->] Queueing: [FORM-GET] {resultUrl}");
                        }
                        else
                        {
                            Console.WriteLine($"    [->] Queueing: [FORM-POST] {submitUrl} (Inputs: {string.Join(", ", formParams.Keys)})");
                        }
                    }
                }
            }
        }
        private async Task ExtractLinksFromScriptTags(
            string rootUrl,
            string currentUrl,
            HtmlDocument doc,
            List<CrawlResult> results)
        {
            var scriptNodes = doc.DocumentNode.SelectNodes("//script");
            if (scriptNodes == null) return;
            foreach (var script in scriptNodes)
            {
                string jsContent = "";

                string src = script.GetAttributeValue("src", "");
                if (string.IsNullOrEmpty(src))
                {
                    jsContent = script.InnerText;
                }
                else
                {
                    string? fullJsUrl = NormalizeUrl(rootUrl, currentUrl, src);
                    if (fullJsUrl == null) continue;

                    try
                    {
                        jsContent = await _client.GetStringAsync(fullJsUrl);
                    }
                    catch { continue; }
                }

                if (string.IsNullOrWhiteSpace(jsContent)) continue;
                ParseJsForEndpoints(rootUrl, currentUrl, jsContent, results);
            }
        }

        private void ParseJsForEndpoints(
            string rootUrl,
            string currentUrl,
            string jsContent,
            List<CrawlResult> results)
        {
            // Pattern GET: cover XMLHttpRequest, fetch(), axios, string literal có query
            var getPatterns = new[]
            {
                @"open\s*\(\s*['""]GET['""]\s*,\s*['""]([^'""]+)['""]",   // open ( "GET" , "URL_CẦN_BẮT"
                @"fetch\s*\(\s*['""]([^'""]+\.php[^'""]*)['""]",           // fetch( "URL_CÓ_ĐUÔI_.php..."
                @"axios\.get\s*\(\s*['""]([^'""]+)['""]",                  // axios.get( "URL"
                @"['""]([a-zA-Z0-9_.~\-/]+\.php\?[^'""]+)['""]",          // URL có query string
            };

            // Pattern POST
            var postPatterns = new[]
            {
                @"open\s*\(\s*['""]POST['""]\s*,\s*['""]([^'""]+)['""]",  // open('POST', "URL", true)
                @"axios\.post\s*\(\s*['""]([^'""]+)['""]",
            };

            // Xử lý GET
            foreach (var pattern in getPatterns)
            {
                foreach (Match m in Regex.Matches(jsContent, pattern, RegexOptions.IgnoreCase))
                {
                    string rawUrl = m.Groups[1].Value;
                    string? fullUrl = NormalizeUrl(rootUrl, currentUrl, rawUrl);
                    if (fullUrl == null) continue;

                    if (fullUrl.Contains("?"))
                    {
                        var uri = new Uri(fullUrl);
                        var queryParams = HttpUtility.ParseQueryString(uri.Query);
                        var paramNames = queryParams.AllKeys.Where(k => k != null).ToList();
                        if (paramNames.Count == 0) continue;

                        string signature = GetUrlSignature(fullUrl, "GET", paramNames);
                        if (_scannedSignatures.Contains(signature)) continue;

                        _scannedSignatures.Add(signature);
                        var paramsDict = paramNames.ToDictionary(k => k, k => queryParams[k] ?? "");

                        // Lọc các URL rác (có thâm số query nhưng không có giá trị)
                        var validParams = paramsDict.Where(p => !string.IsNullOrEmpty(p.Value))
                                                    .ToDictionary(p => p.Key, p => p.Value);

                        if (validParams.Count == 0)
                        {
                            Console.WriteLine($"    [SKIP] Bỏ qua {fullUrl} - tham số không có giá trị");
                            continue;
                        }

                        results.Add(new CrawlResult
                        {
                            FullUrl = fullUrl,
                            HttpMethod = "GET",
                            IsForm = false,
                            Params = validParams
                        });
                        Console.WriteLine($"    [+] JS-GET endpoint: {fullUrl}");
                    }
                }
            }

            // Xử lý POST — chỉ lấy URL, params cần phân tích thêm
            foreach (var pattern in postPatterns)
            {
                foreach (Match m in Regex.Matches(jsContent, pattern, RegexOptions.IgnoreCase))
                {
                    string rawUrl = m.Groups[1].Value;
                    string? fullUrl = NormalizeUrl(rootUrl, currentUrl, rawUrl);
                    if (fullUrl == null) continue;

                    // Cố gắng tìm send() gần nhất để extract params
                    // VD: httpreq.send('id='+which) -> tìm thấy param "id"
                    var sendMatch = Regex.Match(jsContent,
                        @"\.send\s*\(\s*['""]([^'""]+)['""]\s*\)");

                    var paramsDict = new Dictionary<string, string>();
                    if (sendMatch.Success)
                    {
                        var postParams = HttpUtility.ParseQueryString(sendMatch.Groups[1].Value);
                        foreach (string? key in postParams.AllKeys)
                            if (key != null) paramsDict[key] = postParams[key] ?? "TEST";
                    }

                    string signature = GetUrlSignature(fullUrl, "POST", paramsDict.Keys);
                    if (_scannedSignatures.Contains(signature)) continue;

                    _scannedSignatures.Add(signature);

                    var validParams = paramsDict.Where(p => !string.IsNullOrEmpty(p.Value))
                            .ToDictionary(p => p.Key, p => p.Value);

                    if (validParams.Count == 0)
                    {
                        Console.WriteLine($"    [SKIP] Bỏ qua {fullUrl} — tham số không có giá trị");
                        continue;
                    }

                    results.Add(new CrawlResult
                    {
                        FullUrl = fullUrl,
                        HttpMethod = "POST",
                        IsForm = false,
                        Params = validParams
                    });
                    Console.WriteLine($"    [+] JS-POST endpoint: {fullUrl} (Params: {string.Join(", ", paramsDict.Keys)})");
                }
            }
        }

        private string GuessInputValue(HtmlNode inputNode, string inputName, string inputType)
        {
            // Nếu là thẻ <select>, cố gắng lấy giá trị của <option> đầu tiên
            if (inputNode.Name.ToLower() == "select")
            {
                var firstOption = inputNode.SelectSingleNode(".//option[@value]");
                if (firstOption != null) return firstOption.GetAttributeValue("value", "1");
                return "1";
            }

            //Dựa vào type= của thẻ input (chính xác nhất)
            switch (inputType)
            {
                case "email": return "test@example.com";
                case "number": return "1";
                case "tel": return "0123456789";
                case "date": return "2024-01-01";
                case "password": return "Admin@123";
                case "checkbox": return "on";
                case "radio": return "on";
                case "url": return "http://example.com";
            }

            //Dựa vào name= (đoán theo tên biến)
            string nameLower = inputName.ToLower();
            if (nameLower.Contains("email") || nameLower.Contains("mail"))
                return "test@test.com";

            if (nameLower.Contains("phone") || nameLower.Contains("tel")
             || nameLower.Contains("mobile"))
                return "0123456789";

            if (nameLower.Contains("pass") || nameLower.Contains("pwd"))
                return "Test1234!";

            if (nameLower.Contains("id") || nameLower.Contains("num")
             || nameLower.Contains("page") || nameLower.Contains("limit")
             || nameLower.Contains("count"))
                return "1";

            if (nameLower.Contains("age") || nameLower.Contains("year")) return "20";

            if (nameLower.Contains("url") || nameLower.Contains("link")
             || nameLower.Contains("site") || nameLower.Contains("web"))
                return "http://test.com";

            if (nameLower.Contains("date") || nameLower.Contains("time"))
                return "2000-01-01";

            if (nameLower.Contains("user") || nameLower.Contains("name")) return "admin";

            //Dựa vào placeholder= nếu có
            string placeholder = inputNode.GetAttributeValue("placeholder", "");
            if (!string.IsNullOrEmpty(placeholder))
            {
                string phLower = placeholder.ToLower();
                if (phLower.Contains("email") || phLower.Contains("@")) return "test@test.com";
                if (phLower.Contains("phone") || Regex.IsMatch(placeholder, @"^(\+84|0)[0-9]{9}$")) return "0123456789";
                if (phLower.Contains("number") || phLower.Contains("số")) return "1";
            }

            return "TEST";
        }

        // Trả về đường dẫn tuyệt đối
        private string? NormalizeUrl(string rootHostUrl, string currentContextUrl, string relativeUrl)
        {
            try
            {
                Uri rootUri = new Uri(rootHostUrl);
                Uri contextUri = new Uri(currentContextUrl);
                Uri fullUri = new Uri(contextUri, relativeUrl);
                if (!string.Equals(rootUri.Host, fullUri.Host, StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }
                return fullUri.AbsoluteUri;
            }
            catch
            {
                return null;
            }
        }
    }
}
