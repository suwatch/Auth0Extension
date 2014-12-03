using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web.Script.Serialization;

namespace Auth0Module
{
    public class Auth0Token
    {
        public static readonly DateTime EpochTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public string access_token { get; set; }
        public string token_type { get; set; }
        public string id_token { get; set; }

        // calculated
        public IDictionary<string, object> claims { get; set; }

        public static Auth0Token FromStream(Stream stream)
        {
            var serializer = new JavaScriptSerializer();
            using (var reader = new StreamReader(stream))
            {
                var token = serializer.Deserialize<Auth0Token>(reader.ReadToEnd());
                token.Initialize();
                return token;
            }
        }

        private void Initialize()
        {
            var webRequest = (HttpWebRequest)WebRequest.Create("https://" + Auth0Module.Auth0Domain + "/userinfo");
            webRequest.Headers.Add("Authorization", String.Format("Bearer {0}", access_token));
            var webResponse = (HttpWebResponse)webRequest.GetResponse();

            var serializer = new JavaScriptSerializer();
            using (var stream = webResponse.GetResponseStream())
            {
                using (var reader = new StreamReader(stream))
                {
                    claims = serializer.Deserialize<Dictionary<string, object>>(reader.ReadToEnd());

                    Auth0Trace.WriteLine("principal = {0} claims", claims.Count);
                }
            }

            // add exp
            var base64 = id_token.Split('.')[1];
            int mod4 = base64.Length % 4;
            if (mod4 > 0)
            {
                base64 += new string('=', 4 - mod4);
            }

            var jwt = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
            var json = serializer.Deserialize<Dictionary<string, object>>(jwt);
            claims["exp"] = json["exp"];
        }

        public bool IsValid()
        {
            var principal = GetPrincipal();
            var exp = principal.FindFirst("exp");
            var secs = Int32.Parse(exp.Value);
            return DateTime.UtcNow <= EpochTime.AddSeconds(secs);
        }

        public static Auth0Token FromBytes(byte[] bytes)
        {
            var serializer = new JavaScriptSerializer();
            using (var stream = new MemoryStream(bytes))
            {
                using (var reader = new StreamReader(stream))
                {
                    return serializer.Deserialize<Auth0Token>(reader.ReadToEnd());
                }
            }
        }

        public byte[] ToBytes()
        {
            var serializer = new JavaScriptSerializer();
            return Encoding.UTF8.GetBytes(serializer.Serialize(this));
        }

        public ClaimsPrincipal GetPrincipal()
        {
            var list = new List<Claim>();
            foreach (var pair in claims)
            {
                AddClaim(list, pair.Key, pair.Value);
            }

            var identity = new ClaimsIdentity(list, "live");
            return new ClaimsPrincipal(identity);
        }

        static void AddClaim(List<Claim> claims, string key, object value)
        {
            if (value == null)
            {
                //claims.Add(new Claim(key, "<null>"));
            }
            else if (value is object[])
            {
                var items = (object[])value;
                for (int i = 0; i < items.Length; ++i)
                {
                    AddClaim(claims, String.Format("{0}[{1}]", key, i), items[i]);
                }
            }
            else if (value is ArrayList)
            {
                var array = (ArrayList)value;
                for (int i = 0; i < array.Count; ++i)
                {
                    AddClaim(claims, String.Format("{0}[{1}]", key, i), array[i]);
                }
            }
            else if (value is Dictionary<string, object>)
            {
                var dict = (Dictionary<string, object>)value;
                foreach (var item in dict)
                {
                    AddClaim(claims, String.Format("{0}.{1}", key, item.Key), item.Value);
                }
            }
            else
            {
                claims.Add(new Claim(key, value.ToString(), value.GetType().Name));
            }
        }
    }
}