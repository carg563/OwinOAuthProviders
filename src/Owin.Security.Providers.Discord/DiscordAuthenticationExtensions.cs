﻿using System;

namespace Owin.Security.Providers.Discord
{
    public static class DiscordAuthenticationExtensions
    {
        public static IAppBuilder UseDiscordAuthentication(this IAppBuilder app,
            DiscordAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(DiscordAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseDiscordAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseDiscordAuthentication(new DiscordAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}