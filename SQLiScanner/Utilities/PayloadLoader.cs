using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Utility;

namespace SQLiScanner.Utilities
{
    public static class PayloadLoader
    {
        private static ConcurrentDictionary<int, List<PayloadType>> _cachedPayloads = new();
        private static List<Boundary> _cachedBoundaries;
        private static ConcurrentDictionary<DatabaseType, ExploitationTemplate> _cachedExploits = new();

        private static readonly SemaphoreSlim _boundaryLock = new SemaphoreSlim(1, 1);
        private static readonly SemaphoreSlim _payloadLock = new SemaphoreSlim(1, 1);
        private static readonly SemaphoreSlim _exploitLock = new SemaphoreSlim(1, 1);

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
                //Logger.Success("Đã load thành công boundary!");
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

        public static async Task<List<PayloadType>> LoadPayloadAsync(string filePath, int stype)
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

                var payloads = new List<PayloadType>();

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

                            var test = new PayloadType
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
                //Logger.Success($"Đã load thành công {payloads.Count} payloads (stype={stype}))");
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

        public static async Task<ExploitationTemplate> LoadExploitationTemplate(DatabaseType dbType, string directoryPath)
        {
            if (_cachedExploits.TryGetValue(dbType, out var cachedPayloads)) 
                return cachedPayloads;

            await _exploitLock.WaitAsync();
            try
            {
                if (_cachedExploits.TryGetValue(dbType, out var doubleCheckedTemplate))
                    return doubleCheckedTemplate;

                string fileName = dbType switch
                {
                    DatabaseType.MySQL => "mysql.xml",
                    DatabaseType.MSSQL => "mssql.xml",
                    DatabaseType.Oracle => "oracle.xml",
                    DatabaseType.PostgreSQL => "postgresql.xml",
                    DatabaseType.SQLite => "sqlite.xml",
                    _ => throw new Exception("Unsupported Database Type for Exploitation")
                };

                string fullPath = Path.Combine(directoryPath, fileName);
                if (!File.Exists(fullPath))
                    throw new FileNotFoundException($"Không tìm thấy file XML: {fullPath}");

                XDocument xDoc;
                using (var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true))
                {
                    xDoc = await XDocument.LoadAsync(stream, LoadOptions.None, CancellationToken.None);
                }

                var root = xDoc.Element("exploitation");

                ExploitationTemplate template = new ExploitationTemplate
                {
                    Dbms = root?.Attribute("dbms")?.Value ?? dbType.ToString()
                };

                // Parse Queries
                var queriesNode = root?.Element("queries");
                if (queriesNode != null)
                {
                    foreach (var queryNode in queriesNode.Elements("query"))
                    {
                        string target = queryNode.Attribute("target")?.Value ?? "unknown";
                        template.Queries[target] = queryNode.Value.Trim();
                    }
                }

                // Parse Error Based
                var errorNode = root?.Element("error_based");
                if (errorNode != null)
                {
                    template.ErrorTemplate = errorNode.Element("template")?.Value.Trim() ?? "";
                    template.ErrorGrep = errorNode.Element("grep")?.Value.Trim() ?? "";
                }

                // Parse Blind Based
                var blindNode = root?.Element("blind_based");
                if (blindNode != null)
                {
                    template.BlindLengthCondition = blindNode.Element("length_condition")?.Value.Trim() ?? "";
                    template.BlindCharCondition = blindNode.Element("char_condition")?.Value.Trim() ?? "";
                }

                // Parse Time Based
                var timeNode = root?.Element("time_based");
                if (timeNode != null)
                {
                    template.TimeLengthCondition = timeNode.Element("length_condition")?.Value.Trim() ?? "";
                    template.TimeCharCondition = timeNode.Element("char_condition")?.Value.Trim() ?? "";
                }

                // Parse Union Based 
                var unionNode = root?.Element("union_based");
                if (unionNode != null)
                {
                    template.UnionTemplate = unionNode.Element("template")?.Value.Trim() ?? "";
                    template.UnionColumnTemplate = unionNode.Element("column_template")?.Value.Trim() ?? "";
                    template.UnionGrep = unionNode.Element("grep")?.Value.Trim() ?? "";
                }

                _cachedExploits[dbType] = template;
                return template;
            }
            finally
            {
                _exploitLock.Release();
            }
        }

        public static async Task ClearCache()
        {
            await _boundaryLock.WaitAsync();
            try {_cachedBoundaries.Clear(); }
            finally { _boundaryLock.Release(); }        

            await _payloadLock.WaitAsync();
            try {_cachedPayloads.Clear();}
            finally { _payloadLock.Release(); }

            await _exploitLock.WaitAsync();
            try { _cachedExploits.Clear(); }
            finally { _exploitLock.Release(); }
            
        }
    }
}
