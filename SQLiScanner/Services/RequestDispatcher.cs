using Microsoft.Extensions.Logging;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Services
{
    public class RequestDispatcher : IRequestDispatcher
    {
        private readonly HttpClient _client;
        public RequestDispatcher(HttpClient client)
        {
            _client = client;
        }
        public async Task<(string Html, byte[] Bytes, int StatusCode, string FinalUrl, HttpResponseHeaders? Headers)> RequestAsync(
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            try
            {
                var method = new HttpMethod(target.HttpMethod.ToUpper());
                HttpRequestMessage request;

                var queryParams = System.Web.HttpUtility.ParseQueryString(target.RawQueryString);
                var bodyParams = new Dictionary<string, string>(target.Params);

                bool isQueryParam = target.RawQueryString.Contains($"{route.TargetKey}=") ||
                                                                  (!target.Params.ContainsKey(route.TargetKey) && route.Type != RouteType.Cookie);

                string valueToInject = route.Type switch
                {
                    RouteType.Cookie => route.OriginalValue,
                    _ => payload
                };

                if (isQueryParam)
                {
                    queryParams[route.TargetKey] = valueToInject;
                    bodyParams.Remove(route.TargetKey);
                }
                else
                {
                    if (route.Type != RouteType.Cookie) bodyParams[route.TargetKey] = valueToInject;
                }

                var uriBuilder = new UriBuilder(target.BaseUrl)
                {
                    Query = queryParams.ToString()
                };

                request = new HttpRequestMessage(method, uriBuilder.ToString());
                request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

                if (method == HttpMethod.Post)
                {
                    request.Content = new FormUrlEncodedContent(bodyParams);
                    //Logger.Request(method.ToString(), $"URL Query: {uriBuilder.Query} | Body: {string.Join(", ", bodyParams.Select(kv => $"{kv.Key}=[{kv.Value}]"))}");
                }
                else
                {
                    //Logger.Request(method.ToString(), uriBuilder.ToString());
                }


                string baseSessionCookie = target.OriginalCookie;

                if (route.Type == RouteType.Cookie)
                {
                    var cookieBuilder = new StringBuilder();
                    cookieBuilder.Append(route.TargetKey).Append('=').Append(payload);

                    // Nối chuỗi các cookie cũ đảm bảo khi gửi không thiếu dữ liệu
                    if (!string.IsNullOrEmpty(baseSessionCookie))
                    {
                        cookieBuilder.Append("; ").Append(baseSessionCookie);
                    }

                    request.Headers.Add("Cookie", cookieBuilder.ToString());
                    //Logger.Info($"[Routing] Chuyển đổi định tuyến payload: Gửi [{payload}] qua Header Cookie.");
                }
                else
                {
                    if (!string.IsNullOrEmpty(baseSessionCookie))
                    {
                        request.Headers.Add("Cookie", baseSessionCookie);
                    }
                }

                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
                var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                var charset = response.Content.Headers.ContentType?.CharSet;
                var encoding = charset is not null ? Encoding.GetEncoding(charset) : Encoding.UTF8;
                string? finalUrl = response.RequestMessage.RequestUri.ToString();

                return (encoding.GetString(bytes), bytes, (int)response.StatusCode, finalUrl, response.Headers);
            }
            catch (OperationCanceledException)
            {
                //Logger.Warning("Yêu cầu mạng bị hủy bỏ theo yêu cầu của hệ thống/người dùng.");
                return (null!, null!, 0, null!,null!);
            }
            catch (Exception ex)
            {
                //Logger.Error($"Gửi Request thất bại: {ex.Message}");
                return (null!, null!, 0, null!, null!);
            }
        }
    }
}
