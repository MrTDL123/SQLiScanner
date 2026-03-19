using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
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
}
