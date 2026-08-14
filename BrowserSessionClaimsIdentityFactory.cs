using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// A factory for claims identities that works with browser sessions, if enabled.
	/// </summary>
	/// <typeparam name="U">The type of the user, derived from <see cref="User"/>.</typeparam>
	public class BrowserSessionClaimsIdentityFactory<U> : ClaimsIdentityFactory<IdentityUser<U>, long>
		where U : User
	{
		#region Private fields

		private readonly IOwinContext context;

		#endregion

		#region Construction

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="context">The OWIN context.</param>
		public BrowserSessionClaimsIdentityFactory(IOwinContext context)
		{
			if (context == null) throw new ArgumentNullException(nameof(context));

			this.context = context;
		}

		#endregion

		#region Public methods

		/// <summary>
		/// Returns the ID of the user as a string.
		/// </summary>
		public override string ConvertIdToString(long key) => key.ToString();

		/// <summary>
		/// Create the standard claims for the user and, when the request carries a browser session,
		/// add its fingerprint (and any impersonation marker) so that the identity stays paired with
		/// the browser session used to resolve its security stamp.
		/// </summary>
		/// <remarks>
		/// The security stamp baked into the identity by the base factory is resolved through the
		/// current browser-session fingerprint (see <see cref="BrowserSessionUserStore{U}.GetSecurityStampAsync(IdentityUser{U})"/>).
		/// The fingerprint is resolved here the same way the store resolves it, via
		/// <see cref="BrowserSessionClaimAccessor"/>, rather than relying solely on the "ValidatedIdentity"
		/// OWIN environment entry: that entry is only populated during cookie validation, so paths that
		/// re-issue an identity outside that flow (for example a manual re-issue from a controller) would
		/// otherwise produce a cookie without a fingerprint, which the security-stamp validator later rejects.
		/// </remarks>
		public override async Task<ClaimsIdentity> CreateAsync(UserManager<IdentityUser<U>, long> manager, IdentityUser<U> user, string authenticationType)
		{
			var newIdentity = await base.CreateAsync(manager, user, authenticationType);

			AddClaimIfMissing(newIdentity, IdentityClaimNames.Fingerprint, BrowserSessionClaimAccessor.FindFirstValue(context, IdentityClaimNames.Fingerprint));
			AddClaimIfMissing(newIdentity, IdentityClaimNames.ImpersonatedBy, BrowserSessionClaimAccessor.FindFirstValue(context, IdentityClaimNames.ImpersonatedBy));

			return newIdentity;
		}

		#endregion

		#region Private methods

		/// <summary>
		/// Add a claim of the given <paramref name="claimType"/> and <paramref name="value"/> to
		/// <paramref name="identity"/>, unless the value is null or a claim of that type already exists.
		/// </summary>
		private static void AddClaimIfMissing(ClaimsIdentity identity, string claimType, string value)
		{
			if (value == null) return;

			if (identity.FindFirst(claimType) != null) return;

			identity.AddClaim(new Claim(claimType, value));
		}

		#endregion
	}
}
