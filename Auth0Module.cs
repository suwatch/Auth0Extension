using System;
using System.Configuration;
using System.Globalization;
using System.IdentityModel;
using System.IdentityModel.Services;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Script.Serialization;

namespace Auth0Module
{
    // spec: https://docs.auth0.com/protocols
    public class Auth0Module : IHttpModule
    {
        public const string LiveAuth = "Auth0OAuth";
        public const string DeleteCookieFormat = "{0}=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
        public const int CookieChunkSize = 2000;

        public const string LoginCallbackPath = "/login/callback";
        public const string LogoutPath = "/logout";
        public const string LogoutCompletePath = "/logout/complete";

        public static readonly CookieTransform[] DefaultCookieTransforms = new CookieTransform[]
        {
	        new DeflateCookieTransform(),
	        new MachineKeyTransform()
        };


        public static string Auth0ClientId
        {
            get { return ConfigurationManager.AppSettings["Auth0ClientId"]; }
        }

        public static string Auth0ClientSecret
        {
            get { return ConfigurationManager.AppSettings["Auth0ClientSecret"]; }
        }

        public static string Auth0Domain
        {
            get { return ConfigurationManager.AppSettings["Auth0Domain"]; }
        }

        public bool Enabled
        {
            get { return !String.IsNullOrEmpty(Auth0ClientId) && !String.IsNullOrEmpty(Auth0ClientSecret) && !String.IsNullOrEmpty(Auth0Domain); }
        }

        public void Init(HttpApplication context)
        {
            // disable the feature if configuration is not defined
            if (Enabled)
            {
                context.AuthenticateRequest += AuthenticateRequest;
            }
        }

        public void Dispose()
        {
        }

        public void AuthenticateRequest(object sender, EventArgs e)
        {
            var application = (HttpApplication)sender;
            var request = application.Request;
            var requestUrl = new Uri(request.Url, request.RawUrl);
            var response = application.Response;

            Auth0Trace.WriteLine("request = {0}", requestUrl);

            if (requestUrl.AbsolutePath.StartsWith(LogoutPath, StringComparison.OrdinalIgnoreCase))
            {
                if (requestUrl.AbsolutePath.Equals(LogoutPath, StringComparison.OrdinalIgnoreCase))
                {
                    RemoveSessionCookie(application);

                    response.Redirect(GetLogoutUrl(application), endResponse: true);
                }
                else
                {
                    response.Write("<a href=\"/\">login</a>");
                    application.CompleteRequest();
                }

                return;
            }

            string redirectUri;
            var token = AuthenticateUser(application, out redirectUri);
            if (token == null)
            {
                redirectUri = redirectUri ?? GetLoginUrl(application);
            }

            if (!String.IsNullOrEmpty(redirectUri))
            {
                Auth0Trace.WriteLine("redirectUri = {0}", redirectUri);

                response.Redirect(redirectUri, endResponse: true);
                return;
            }

            var principal = token.GetPrincipal();
            HttpContext.Current.User = principal;
            Thread.CurrentPrincipal = principal;
        }

        public static string GetLoginUrl(HttpApplication application)
        {
            var request = application.Context.Request;
            var requestUrl = new Uri(request.Url, request.RawUrl);
            var loginAddress = String.Format("https://{0}/authorize", Auth0Domain);
            var client_id = Auth0ClientId;
            var scope = "openid profile";
            var response_type = "code";
            var redirect_uri = GetRedirectUrl(application);
            var state = requestUrl.AbsolutePath; // no query

            StringBuilder strb = new StringBuilder();
            strb.Append(loginAddress);
            strb.AppendFormat("?client_id={0}", WebUtility.UrlEncode(client_id));
            strb.AppendFormat("&scope={0}", WebUtility.UrlEncode(scope));
            strb.AppendFormat("&response_type={0}", WebUtility.UrlEncode(response_type));
            strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirect_uri));
            strb.AppendFormat("&state={0}", WebUtility.UrlEncode(state));

            return strb.ToString();
        }

        // spec: https://docs.auth0.com/logout
        public static string GetLogoutUrl(HttpApplication application)
        {
            var request = application.Context.Request;
            var logoutAddress = String.Format("https://{0}/logout", Auth0Domain);
            var returnTo = request.Url.GetLeftPart(UriPartial.Authority) + LogoutCompletePath;

            StringBuilder strb = new StringBuilder();
            strb.Append(logoutAddress);
            strb.AppendFormat("?returnTo={0}", WebUtility.UrlEncode(returnTo));

            return strb.ToString();
        }

        public static byte[] EncodeCookie(Auth0Token token)
        {
            var bytes = token.ToBytes();
            for (int i = 0; i < DefaultCookieTransforms.Length; ++i)
            {
                bytes = DefaultCookieTransforms[i].Encode(bytes);
            }
            return bytes;
        }

        public static Auth0Token DecodeCookie(byte[] bytes)
        {
            try
            {
                for (int i = DefaultCookieTransforms.Length - 1; i >= 0; --i)
                {
                    bytes = DefaultCookieTransforms[i].Decode(bytes);
                }
                return Auth0Token.FromBytes(bytes);
            }
            catch (Exception ex)
            {
                Auth0Trace.WriteLine("DecodeCookie failed with {0}", ex);

                // bad cookie
                return null;
            }
        }
        public static Auth0Token AuthenticateUser(HttpApplication application, out string redirectUri)
        {
            redirectUri = null;

            var request = application.Context.Request;
            var requestUrl = new Uri(request.Url, request.RawUrl);
            if (!requestUrl.AbsolutePath.Equals(LoginCallbackPath, StringComparison.OrdinalIgnoreCase))
            {
                return ReadSessionCookie(application);
            }

            var query = HttpUtility.ParseQueryString(requestUrl.Query);
            var code = query["code"];
            if (String.IsNullOrEmpty(code))
            {
                return ReadSessionCookie(application);
            }

            var tokenRequestUri = String.Format("https://{0}/oauth/token", Auth0Domain);
            var client_id = Auth0ClientId;
            var client_secret = Auth0ClientSecret;
            var redirect_uri = GetRedirectUrl(application);

            var payload = new StringBuilder("grant_type=authorization_code");
            payload.AppendFormat("&client_id={0}", WebUtility.UrlEncode(client_id));
            payload.AppendFormat("&client_secret={0}", WebUtility.UrlEncode(client_secret));
            payload.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirect_uri));
            payload.AppendFormat("&code={0}", WebUtility.UrlEncode(code));

            var webRequest = (HttpWebRequest)WebRequest.Create(tokenRequestUri);
            webRequest.Method = "POST";
            webRequest.ContentType = "application/x-www-form-urlencoded";
            using (var stream = webRequest.GetRequestStream())
            {
                var bytes = Encoding.UTF8.GetBytes(payload.ToString());
                stream.Write(bytes, 0, bytes.Length);
            }

            try
            {
                var webResponse = (HttpWebResponse)webRequest.GetResponse();
                using (var stream = webResponse.GetResponseStream())
                {
                    var token = Auth0Token.FromStream(stream);

                    WriteSessionCookie(application, token);

                    redirectUri = query["state"];

                    return token;
                }
            }
            catch (WebException ex)
            {
                Auth0Trace.WriteLine("POST {0} failed with {1}", tokenRequestUri, ex);

                throw HandleOAuthError(ex, tokenRequestUri);
            }
        }

        public static Auth0Token ReadSessionCookie(HttpApplication application)
        {
            var request = application.Context.Request;

            // read user cookie
            var cookies = request.Cookies;
            var strb = new StringBuilder();
            int index = 0;
            while (true)
            {
                var cookieName = LiveAuth;
                if (index > 0)
                {
                    cookieName += index.ToString(CultureInfo.InvariantCulture);
                }

                var cookie = cookies[cookieName];
                if (cookie == null)
                {
                    break;
                }

                strb.Append(cookie.Value);
                ++index;
            }

            if (strb.Length == 0)
            {
                return null;
            }

            var bytes = Convert.FromBase64String(strb.ToString());
            var token = DecodeCookie(bytes);
            if (token == null || !token.IsValid())
            {
                RemoveSessionCookie(application);

                return null;
            }

            return token;
        }

        public static void WriteSessionCookie(HttpApplication application, Auth0Token token)
        {
            var request = application.Context.Request;
            var response = application.Context.Response;

            var bytes = EncodeCookie(token);
            var cookie = Convert.ToBase64String(bytes);
            var chunkCount = cookie.Length / CookieChunkSize + (cookie.Length % CookieChunkSize == 0 ? 0 : 1);
            for (int i = 0; i < chunkCount; ++i)
            {
                var setCookie = new StringBuilder();
                setCookie.Append(LiveAuth);
                if (i > 0)
                {
                    setCookie.Append(i.ToString(CultureInfo.InvariantCulture));
                }

                setCookie.Append('=');

                int startIndex = i * CookieChunkSize;
                setCookie.Append(cookie.Substring(startIndex, Math.Min(CookieChunkSize, cookie.Length - startIndex)));
                setCookie.Append("; path=/");
                if (request.Url.Scheme == "https")
                {
                    setCookie.Append("; secure");
                }
                setCookie.Append("; HttpOnly");
                response.Headers.Add("Set-Cookie", setCookie.ToString());
            }

            var cookies = request.Cookies;
            var index = chunkCount;
            while (true)
            {
                var cookieName = LiveAuth;
                if (index > 0)
                {
                    cookieName += index.ToString(CultureInfo.InvariantCulture);
                }

                if (cookies[cookieName] == null)
                {
                    break;
                }

                // remove old cookie
                response.Headers.Add("Set-Cookie", String.Format(DeleteCookieFormat, cookieName));
                ++index;
            }
        }

        public static void RemoveSessionCookie(HttpApplication application)
        {
            var request = application.Context.Request;
            var response = application.Context.Response;

            var cookies = request.Cookies;
            foreach (string name in new[] { LiveAuth })
            {
                int index = 0;
                while (true)
                {
                    string cookieName = name;
                    if (index > 0)
                    {
                        cookieName += index.ToString(CultureInfo.InvariantCulture);
                    }

                    if (cookies[cookieName] == null)
                    {
                        break;
                    }

                    // remove old cookie
                    response.Headers.Add("Set-Cookie", String.Format(DeleteCookieFormat, cookieName));
                    ++index;
                }
            }
        }

        static Exception HandleOAuthError(WebException ex, string requestUri)
        {
            var response = ex.Response;
            if (response != null)
            {
                using (var stream = response.GetResponseStream())
                {
                    var error = Auth0OAuthError.FromStream(stream);
                    if (error != null && !String.IsNullOrEmpty(error.error_description))
                    {
                        return new InvalidOperationException(String.Format("Failed with {0}  POST {1}", error.error_description, requestUri), ex);
                    }
                }
            }

            return new InvalidOperationException(String.Format("Failed with {0}  POST {1}", ex.Message, requestUri), ex);
        }

        static string GetRedirectUrl(HttpApplication application)
        {
            var request = application.Context.Request;
            return request.Url.GetLeftPart(UriPartial.Authority) + LoginCallbackPath;
        }

        public class Auth0OAuthError
        {
            public string error { get; set; }
            public string error_description { get; set; }

            public static Auth0OAuthError FromStream(Stream stream)
            {
                var serializer = new JavaScriptSerializer();
                using (var reader = new StreamReader(stream))
                {
                    var token = serializer.Deserialize<Auth0OAuthError>(reader.ReadToEnd());
                    return token;
                }
            }
        }
    }
}