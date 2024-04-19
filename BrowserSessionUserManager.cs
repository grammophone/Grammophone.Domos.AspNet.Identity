using System;
using System.Collections.Generic;
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
	}
}
