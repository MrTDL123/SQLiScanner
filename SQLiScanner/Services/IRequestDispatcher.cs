using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Services
{
    public interface IRequestDispatcher
    {
        Task<(string Html, byte[] Bytes, int StatusCode, string FinalUrl, HttpResponseHeaders? Headers)> RequestAsync(
            CrawlResult target,
            string payload,
            InjectionRoute route,
            CancellationToken cancellationToken = default);
    }
}
