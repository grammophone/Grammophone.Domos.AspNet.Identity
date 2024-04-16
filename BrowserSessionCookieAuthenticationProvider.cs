using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.Cookies;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// A cookie authentication provider that enables browser sessions.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	/// <typeparam name="US">The user manager, derived from <see cref="BrowserSessionUserStore{U}"/>.</typeparam>
	public class BrowserSessionCookieAuthenticationProvider<U, US> : CookieAuthenticationProvider
		where U : User
		where US : UserManager<IdentityUser<U>, long>
	{
		#region Public methods

		/// <summary>
		/// If there is no ingerprint in the identity's claims, try to initialize a browser session and add its fingerprint on the claims.
		/// </summary>
		public override async Task ValidateIdentity(CookieValidateIdentityContext context)
		{
			string fingerprint = context.Identity.FindFirstValue("fingerprint");

			if (String.IsNullOrEmpty(fingerprint) && context.Identity != null)
			{
				var userManager = context.OwinContext.GetUserManager<US>();

				if (userManager != null)
				{
					long userID = context.Identity.GetUserId<long>();

					context.OwinContext.Environment.Add("ValidatedIdentity", context.Identity);

					// If the IUserStore descends from BrowserSessionUserStore, force creating a browser session and adding of the fingerprint claim.
					await userManager.GetSecurityStampAsync(userID);
				}
			}

			await base.ValidateIdentity(context);

			fingerprint = context.Identity.FindFirstValue("fingerprint");

			if (String.IsNullOrEmpty(fingerprint) && context.Identity != null)
			{
				context.OwinContext.Authentication.SignIn(context.Properties, context.Identity);
			}
		}

		#endregion
	}
}
