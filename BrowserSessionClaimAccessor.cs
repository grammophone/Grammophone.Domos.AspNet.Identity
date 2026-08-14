using System.Security.Claims;
using System.Threading;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// Resolves browser-session related claims (such as the fingerprint) for the current request
	/// by consulting, in priority order, the ambient thread principal, the OWIN authenticated user
	/// and the identity being validated by the cookie middleware.
	/// </summary>
	internal static class BrowserSessionClaimAccessor
	{
		/// <summary>
		/// The key under which <see cref="BrowserSessionCookieAuthenticationProvider{U, US}"/> stores the
		/// identity being validated inside the OWIN environment.
		/// </summary>
		public const string ValidatedIdentityEnvironmentKey = "ValidatedIdentity";

		/// <summary>
		/// Find the value of the first claim of the given <paramref name="claimType"/> for the current
		/// request, searching in priority order the thread principal, then the OWIN authenticated user,
		/// then the identity being validated by the cookie middleware.
		/// </summary>
		/// <param name="context">The OWIN context of the current request.</param>
		/// <param name="claimType">The type of the claim to find.</param>
		/// <returns>Returns the claim value if found in any of the sources, else null.</returns>
		public static string FindFirstValue(IOwinContext context, string claimType)
		{
			string value = (Thread.CurrentPrincipal?.Identity as ClaimsIdentity)?.FindFirstValue(claimType);

			if (value != null) return value;

			value = (context?.Authentication?.User?.Identity as ClaimsIdentity)?.FindFirstValue(claimType);

			if (value != null) return value;

			if (context != null && context.Environment.TryGetValue(ValidatedIdentityEnvironmentKey, out object identityObject))
			{
				value = (identityObject as ClaimsIdentity)?.FindFirstValue(claimType);

				if (value != null) return value;
			}

			return null;
		}
	}
}
