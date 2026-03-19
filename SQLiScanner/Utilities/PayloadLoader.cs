using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using SQLiScanner.Models;
using SQLiScanner.Utility;

namespace SQLiScanner.Utilities
{
    public static class PayloadLoader
    {
        private static ConcurrentDictionary<int, List<PayloadTest>> _cachedPayloads = new();
        private static List<Boundary> _cachedBoundaries;

        private static readonly SemaphoreSlim _boundaryLock = new SemaphoreSlim(1, 1);
        private static readonly SemaphoreSlim _payloadLock = new SemaphoreSlim(1, 1);

        public static async Task<List<Boundary>> LoadBoundariesAsync(string filePath)
        {
            if (_cachedBoundaries != null)
                return _cachedBoundaries;

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"Không tìm thấy file để load Boundary: {filePath}");

            // Chặn các luồng khác truy cập vào File
            await _boundaryLock.WaitAsync();
            try
            {
                // Kiểm tra lần 2 nếu như luồng trước đó đã load cache
                if (_cachedBoundaries != null)
                    return _cachedBoundaries;

                var boundaries = new List<Boundary>();
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true))
                {
                    XDocument doc = await XDocument.LoadAsync(stream, LoadOptions.None, CancellationToken.None);
                    var boundaryElements = doc.Root?.Elements("boundary") ?? Enumerable.Empty<XElement>();

                    int index = 0;
                    foreach (var element in boundaryElements)
                    {
                        try
                        {
                            boundaries.Add(new Boundary
                            {
                                Level = int.Parse(element.Element("level")?.Value ?? "1"),
                                Clause = element.Element("clause")?.Value ?? "0",
                                Where = element.Element("where")?.Value ?? "1",
                                PType = int.Parse(element.Element("ptype")?.Value ?? "1"),
                                Prefix = element.Element("prefix")?.Value ?? "",
                                Suffix = element.Element("suffix")?.Value ?? "",
                                ContextName = GetContextName(int.Parse(element.Element("ptype")?.Value ?? "1"))
                            });
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning($"Lỗi parse boundary thứ {index}: {ex.Message}");
                        }

                        index++;
                    }
                }

                _cachedBoundaries = boundaries;
                Logger.Success("Đã load thành công boundary!");
                return boundaries;
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi load boundaríes: {ex.Message}", ex);
            }
            finally
            {
                _boundaryLock.Release();
            }
        }

        public static async Task<List<PayloadTest>> LoadPayloadAsync(string filePath, int stype)
        {
            if (_cachedPayloads.TryGetValue(stype, out var cachedPayload))
                return cachedPayload;

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"Không tìm thấy file payload: {filePath}");

            await _payloadLock.WaitAsync();
            try
            {
                if (_cachedPayloads.TryGetValue(stype, out var cachedValueSecondCheck))
                    return cachedValueSecondCheck;

                var payloads = new List<PayloadTest>();

                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true))
                {
                    XDocument doc = await XDocument.LoadAsync(stream, LoadOptions.None, CancellationToken.None);
                    var testElements = doc.Root?.Elements("test") ?? Enumerable.Empty<XElement>();

                    int index = 0;
                    foreach (var element in testElements)
                    {
                        try
                        {
                            int testSType = int.Parse(element.Element("stype")?.Value ?? "0");
                            if (testSType != 0 && testSType != stype)
                                continue;

                            var test = new PayloadTest
                            {
                                Title = element.Element("title")?.Value ?? "",
                                SType = testSType,
                                Level = int.Parse(element.Element("level")?.Value ?? "1"),
                                Risk = int.Parse(element.Element("risk")?.Value ?? "1"),
                                Clause = element.Element("clause")?.Value ?? "0",
                                Where = int.Parse(element.Element("where")?.Value ?? "1"),
                                Vector = element.Element("vector")?.Value ?? "",
                                Comment = element.Element("request")?.Element("comment")?.Value,
                                ComparisonPayload = element.Element("response")?.Element("comparison")?.Value,
                                ErrorResponsePattern = element.Element("grep")?.Value,
                                DBMS = element.Element("dbms")?.Value ?? "Unknown",
                                DBMSVersion = element.Element("details")?.Element("dbms_version")?.Value ?? ""
                            };

                            var payloadElements = element.Elements("payload");
                            if (payloadElements != null)
                            {
                                foreach (var payloadElem in payloadElements)
                                {
                                    test.Payloads.Add(payloadElem.Value);
                                }
                            }

                            if (test.Payloads.Count == 0 && !string.IsNullOrEmpty(test.Vector))
                            {
                                test.Payloads.Add(test.Vector);
                            }

                            // Lấy time delay cho time-based tests
                            var timeElement = element.Element("response")?.Element("time");
                            if (timeElement != null && int.TryParse(timeElement.Value.Replace("[SLEEPTIME]", ""), out int timeVal))
                            {
                                test.TimeDelay = timeVal;
                            }

                            payloads.Add(test);
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning($"Lỗi Parse Payload thứ {index}: {ex.Message}");
                        }

                        index++;
                    }
                }

                _cachedPayloads[stype] = payloads;
                Logger.Success($"Đã load thành công {payloads.Count} payloads (stype={stype}))");
                return payloads;
            }
            catch (Exception ex)
            {
                throw new Exception($"Lỗi load payloads: {ex.Message}", ex);
            }
            finally
            {
                _payloadLock.Release();
            }
        }

        private static string GetContextName(int ptype)
        {
            return ptype switch
            {
                1 => "INTEGER",
                2 => "STRING_SINGLE_QUOTE",
                3 => "LIKE_SINGLE_QUOTE",
                4 => "STRING_DOUBLE_QUOTE",
                5 => "LIKE_DOUBLE_QUOTE",
                6 => "IDENTIFIER",
                _ => "UNKNOWN"
            };
        }

        public static async Task ClearCache()
        {
            await _boundaryLock.WaitAsync();
            try {_cachedBoundaries = null; }
            finally { _boundaryLock.Release(); }        

            await _payloadLock.WaitAsync();
            try {_cachedPayloads.Clear();}
            finally { _payloadLock.Release(); }
            
        }
    }
}
