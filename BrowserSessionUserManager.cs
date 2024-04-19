using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// User manager that uses a user store derived from <see cref="BrowserSessionUserStore{U}"/>
	/// and setting up <see cref="BrowserSessionClaimsIdentityFactory{U}"/> to be used.
	/// </summary>
	/// <typeparam name="U">The user, derived from <see cref="User"/>.</typeparam>
	public class BrowserSessionUserManager<U> : UserManager<IdentityUser<U>, long>
		where U : User
	{
		#region Constrution

		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="store">The user store, derived from <see cref="BrowserSessionUserStore{U}"/>.</param>
		/// <param name="context">The OWIN context.</param>
		public BrowserSessionUserManager(BrowserSessionUserStore<U> store, IOwinContext context) : base(store)
		{
			if (context == null) throw new ArgumentNullException(nameof(context));

			this.Store = store;

			this.ClaimsIdentityFactory = new BrowserSessionClaimsIdentityFactory<U>(context);
		}

		#endregion

		#region Protected properties

		/// <summary>
		/// The user store, derived from <see cref="BrowserSessionUserStore{U}"/>.
		/// </summary>
		protected new BrowserSessionUserStore<U> Store { get; }

		#endregion

		#region Public methods

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="userID">The ID of the user to be logged of.</param>
		/// <param name="fingerprint">The fingerprint of the session to log off.</param>
		/// <exception cref="InvalidOperationException">Thrown when no user was found having the given ID.</exception>
		public async Task LogoffBrowserSessionAsync(long userID, string fingerprint)
		{
			var identityUser = await this.Store.FindByIdAsync(userID);

			if (identityUser == null) throw new InvalidOperationException($"The user with ID {userID} was not found.");

			await this.Store.LogoffBrowserSessionAsync(identityUser, fingerprint);
		}

		/// <summary>
		/// Log off a browser session.
		/// </summary>
		/// <param name="sessionID">The ID of the browser session.</param>
		public Task LogOffBrowserSessionAsync(long sessionID)
			=> this.Store.LogoffBrowserSessionAsync(sessionID);

		/// <summary>
		/// Log off all active sessions of a user.
		/// </summary>
		/// <param name="userID">The ID of the user.</param>
		/// <exception cref="InvalidOperationException">Thrown when no user was found having the given ID.</exception>
		public async Task GlobalLogOffAsync(long userID)
		{
			var identityUser = await this.Store.FindByIdAsync(userID);

			if (identityUser == null) throw new InvalidOperationException($"The user with ID {userID} was not found.");

			await this.Store.GlobalLofOffAsync(identityUser);
		}

		#endregion
	}
}
