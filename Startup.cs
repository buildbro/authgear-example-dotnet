using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace OidcClientDemoApplication
{
    public class Startup
    {

        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration config)
        {
            Environment = environment;
            Configuration = config;
        }

        private void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

                if (DisallowsSameSiteNone(userAgent))
                {
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        public static bool DisallowsSameSiteNone(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
            {
                return false;
            }

            // Cover all iOS based browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
            // All of which are broken by SameSite=None, because they use the iOS networking stack
            if (userAgent.Contains("CPU iPhone OS 12") || userAgent.Contains("iPad; CPU OS 12"))
            {
                return true;
            }

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X.
            // This does not include:
            // - Chrome on Mac OS X
            // Because they do not use the Mac OS networking stack.
            if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14") &&
                userAgent.Contains("Version/") && userAgent.Contains("Safari"))
            {
                return true;
            }

            // Cover Chrome 50-69, because some versions are broken by SameSite=None, 
            // and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions, 
            // but pre-Chromium Edge does not require SameSite=None.
            if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
            {
                return true;
            }

            return false;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseCookiePolicy(); // Before UseAuthentication or anything else that writes cookies.
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // Prevent WS-Federation claim names being written to tokens
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.OnAppendCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext => CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {

                // Set the main OpenID Connect settings
                options.Authority = Configuration.GetValue<string>("OpenIdConnect:Issuer");
                options.ClaimsIssuer = "Authgear";

                options.ClientId = Configuration.GetValue<string>("OpenIdConnect:ClientId");
                options.ClientSecret = Configuration.GetValue<string>("OpenIdConnect:ClientSecret");

                options.ResponseType = OpenIdConnectResponseType.Code;

                var scopeString = Configuration.GetValue<string>("OpenIDConnect:Scope");
                options.Scope.Clear();
                scopeString.Split(" ", StringSplitOptions.TrimEntries).ToList().ForEach(scope =>
                {
                    options.Scope.Add(scope);
                });

                // If required, override the issuer and audience used to validate ID tokens
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = options.Authority,
                    ValidAudience = options.ClientId
                };

                // This example gets user information for display from the user info endpoint
                options.GetClaimsFromUserInfoEndpoint = true;

                // Handle the post logout redirect URI
                options.Events.OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    context.ProtocolMessage.PostLogoutRedirectUri = Configuration.GetValue<string>("OpenIdConnect:PostLogoutRedirectUri");
                    return Task.CompletedTask;
                };

                // Save tokens issued to encrypted cookies
                options.SaveTokens = true;

                // Set this in developer setups if the OpenID Provider uses plain HTTP
                options.RequireHttpsMetadata = false;
            });

            services.AddAuthorization();
            services.AddRazorPages();

            // Add this app's types to dependency injection
            services.AddSingleton<TokenClient>();
        }
    }
}
