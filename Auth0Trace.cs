using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth0Module
{
    public static class Auth0Trace
    {
        private static string _tracePath = @"%HOME%\LogFiles";
        private static string _traceFile = @"auth0trace.txt";

        private static Lazy<bool> _traceEnabled = new Lazy<bool>(() => !String.IsNullOrEmpty(Environment.GetEnvironmentVariable("Auth0TraceEnable")));

        public static void WriteLine(string format, params object[] args)
        {
            if (_traceEnabled.Value)
            {
                var traceFile = GetTraceFile();
                if (traceFile != null)
                {
                    var strb = new StringBuilder();
                    strb.Append(DateTime.UtcNow.ToString("s"));
                    strb.Append(" ");
                    strb.AppendFormat(format, args);

                    using (var writer = traceFile.AppendText())
                    {
                        writer.WriteLine(strb.ToString());
                    }
                }
            }
        }

        private static FileInfo GetTraceFile()
        {
            var path = Environment.ExpandEnvironmentVariables(_tracePath);
            if (!Directory.Exists(path))
            {
                return null;
            }

            var traceFile = new FileInfo(Path.Combine(path, _traceFile));
            if (traceFile.Exists && traceFile.Length > 10 * 1024 * 1024)
            {
                return null;
            }

            return traceFile;
        }
    }
}
