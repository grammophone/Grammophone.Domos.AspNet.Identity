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
		/// If there is a newly validated entity with associated fingerprint, add the fingerprint to along the standard claims.
		/// </summary>
		public override async Task<ClaimsIdentity> CreateAsync(UserManager<IdentityUser<U>, long> manager, IdentityUser<U> user, string authenticationType)
		{
			var newIdentity = await base.CreateAsync(manager, user, authenticationType);

			if (context.Environment.TryGetValue("ValidatedIdentity", out object existingClaimsIdentityObject))
			{
				var existingClaimsIdentity = existingClaimsIdentityObject as ClaimsIdentity;

				if (existingClaimsIdentity != null)
				{
					string fingerprint = existingClaimsIdentity.FindFirstValue(IdentityClaimNames.Fingerprint);

					if (fingerprint != null)
					{
						newIdentity.AddClaim(new Claim(IdentityClaimNames.Fingerprint, fingerprint));
					}
				}
			}

			return newIdentity;
		}

		#endregion
	}
}
