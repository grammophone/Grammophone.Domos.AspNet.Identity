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
			bool addedFingerprintClaim = false;

			if (context.Identity != null)
			{
				context.OwinContext.Environment.Add("ValidatedIdentity", context.Identity);

				string fingerprint = context.Identity.FindFirstValue("fingerprint");

				if (String.IsNullOrEmpty(fingerprint))
				{
					context.Identity.AddClaim(new Claim("fingerprint", Guid.NewGuid().ToString()));

					addedFingerprintClaim = true;

					var userManager = context.OwinContext.GetUserManager<US>();

					if (userManager != null)
					{
						long userID = context.Identity.GetUserId<long>();

						// If the IUserStore descends from BrowserSessionUserStore, force creating a browser session and adding of the fingerprint claim.
						await userManager.GetSecurityStampAsync(userID);
					}
				}
			}

			await base.ValidateIdentity(context);

			if (addedFingerprintClaim && context.Identity != null) // If not rejected and added fingerprint, update sign-on.
			{
				context.OwinContext.Authentication.SignIn(context.Properties, context.Identity);
			}
		}

		#endregion
	}
}
