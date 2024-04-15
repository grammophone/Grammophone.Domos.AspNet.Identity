using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Grammophone.Domos.DataAccess;
using Grammophone.Domos.Domain;
using Microsoft.AspNet.Identity;
using MyCSharp.HttpUserAgentParser;

namespace Grammophone.Domos.AspNet.Identity
{
	/// <summary>
	/// An an ASP.NET Identity user store implementation that tracks browser sessions.
	/// It expects a Unity container defining an <see cref="IUsersDomainContainer{U}"/>,
	/// a <see cref="IPLocation.ILocationProviderFactory"/>, a <see cref="IPLocation.Caching.LocationCache"/>
	/// and optionally any listeners implementing <see cref="IUserListener{U}"/>.
	/// </summary>
	/// <typeparam name="U">The type of the user, descended from <see cref="User"/>.</typeparam>
	public class BrowserSessionUserStore<U> : UserStore<U>
		where U : User
	{
		#region Private propoerties

		private Microsoft.Owin.IOwinContext context;

		#endregion

		#region Construction
		
		/// <summary>
		/// Create.
		/// </summary>
		/// <param name="configurationSectionName">The name of the Unity configuration section where the dependencies are defined.</param>
		/// <param name="context">The OWIN context.</param>
		public BrowserSessionUserStore(string configurationSectionName, Microsoft.Owin.IOwinContext context) : base(configurationSectionName)
		{
			if (context == null) throw new ArgumentNullException(nameof(context));

			this.context = context;
		}

		#endregion

		#region IUserSecurityStampStore<IdentityUser<U>,long> Members

		/// <summary>
		/// If there is a finerprint, try to fetch the security stamp from the corresponding browser session, else fall back to the base implementation
		/// and get it from the user entity directly.
		/// </summary>
		/// <param name="user">The identity user.</param>
		public override async Task<string> GetSecurityStampAsync(IdentityUser<U> user)
		{
			var claimsPrincipal = context.Request?.User as ClaimsPrincipal;

			if (claimsPrincipal != null)
			{
				string fingerprint = ((ClaimsIdentity)claimsPrincipal.Identity).FindFirstValue("fingerprint");

				if (fingerprint != null)
				{
					var browserSessionQuery = from bs in this.DomainContainer.BrowserSessions
																		where bs.UserID == user.DomainUser.ID && bs.FingerPrint == fingerprint
																		select bs;

					var browserSession = await browserSessionQuery.FirstOrDefaultAsync();

					return browserSession.SecurityStamp;
				}
			}

			return await base.GetSecurityStampAsync(user);
		}

		/// <summary>
		/// If possible, use or create a browser session to set the security stamp.
		/// </summary>
		/// <param name="user">THe identity user.</param>
		/// <param name="stamp">The security stamp to set.</param>
		public override async Task SetSecurityStampAsync(IdentityUser<U> user, string stamp)
		{
			var claimsPrincipal = context.Request?.User as ClaimsPrincipal;

			if (claimsPrincipal != null)
			{
				string fingerprint = ((ClaimsIdentity)claimsPrincipal.Identity).FindFirstValue("fingerprint");

				var browserSession = await TryGetOrCreateBrowserSessionAsync(user, fingerprint);

				if (browserSession != null)
				{
					browserSession.SecurityStamp = stamp;
					
					return;
				}
			}

			await base.SetSecurityStampAsync(user, stamp);
		}

		#endregion

		#region Protected methods

		/// <summary>
		/// Parse the 'User-Agent' header and set the <see cref="BrowserSession.Browser"/> and <see cref="BrowserSession.OperatingSystem"/>
		/// propterties.
		/// </summary>
		/// <param name="userAgent">The value of the 'User-Agent' header.</param>
		/// <param name="browserSession">The browser session to update.</param>
		protected virtual Task ParseUserAgentAsync(string userAgent, BrowserSession browserSession)
		{
			if (userAgent == null) throw new ArgumentNullException(nameof(userAgent));
			if (browserSession == null) throw new ArgumentNullException(nameof(browserSession));

			var userAgentInfo = HttpUserAgentParser.Parse(userAgent);
			
			string operatingSystem = userAgentInfo.Platform.HasValue ? userAgentInfo.Platform.Value.Name : null;
			string browser = $"{userAgentInfo.Name} {userAgentInfo.Version}";

			browserSession.OperatingSystem = operatingSystem;
			browserSession.Browser = browser;

			return Task.CompletedTask;
		}

		#endregion

		#region Private methods

		/// <summary>
		/// Get an existing browser based on the finger print or create a new one.
		/// </summary>
		/// <param name="user"></param>
		/// <param name="browserFingerPrint"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentNullException"></exception>
		private async Task<BrowserSession> TryGetOrCreateBrowserSessionAsync(
						IdentityUser<U> user,
						string browserFingerPrint = null)
		{
			if (user == null) throw new ArgumentNullException(nameof(user));

			BrowserSession browserSession = null;

			if (browserFingerPrint == null)
				browserFingerPrint = Guid.NewGuid().ToString();
			else
				browserSession = user.DomainUser.Sessions.Where(bs => bs.FingerPrint == browserFingerPrint).FirstOrDefault();

			//get client info
			var userAgentString = context.Request.Headers.Get("User-Agent");
			var ipAddress = context.Request.RemoteIpAddress;

			if (browserSession == null) //first time
			{
				using (var transaction = this.DomainContainer.BeginTransaction())
				{
					//create browser session.
					browserSession = this.DomainContainer.BrowserSessions.Create();

					if (userAgentString != null)
					{
						await ParseUserAgentAsync(userAgentString, browserSession);
					}
					
					if (!string.IsNullOrEmpty(ipAddress))
					{
						ClientIpAddress clientIpAddress = new ClientIpAddress
						{
							IpAddress = ipAddress,
							LastSeen = DateTime.UtcNow
						};

						//find locatin info
						try
						{
							IPAddress ipadr = IPAddress.Parse(ipAddress);

							// check if we are in a dev environment as the client will be the same machine
							if (IPAddress.IsLoopback(ipadr))
							{
								ipadr = IPAddress.Parse("31.14.242.226");
							}

							var cache = this.Settings.Resolve<IPLocation.Caching.LocationCache>();
							var location = await cache.GetLocationAsync(ipadr);

							clientIpAddress.City = location.City.Name;
							clientIpAddress.Region = location.LastSubdivision.Name;
							clientIpAddress.Country = location.Country.Name;
							clientIpAddress.RawIpServiceData = location.Response;
						}
						catch (Exception ex)
						{
							Trace.TraceWarning($"Could not parse IP address {ipAddress}, reason: {ex.Message}.");
						}

						browserSession.IPAddresses.Add(clientIpAddress);
					}

					browserSession.FingerPrint = browserFingerPrint;

					browserSession.SecurityStamp = Guid.NewGuid().ToString();
					browserSession.LastSeenOn = DateTime.UtcNow;
					browserSession.FirstSignInOn = DateTime.UtcNow;

					user.DomainUser.Sessions.Add(browserSession);

					await transaction.CommitAsync();
				}
			}
			else //returning browser
			{
				//check if the session has been logged out.
				if (browserSession.IsLoggedOff)
				{
					return null;
				}

				//update last seen
				using (var transaction = this.DomainContainer.BeginTransaction())
				{
					browserSession.LastSeenOn = DateTime.UtcNow;

					//if first seen in this address.
					if (!browserSession.IPAddresses.Any(a => a.IpAddress == ipAddress))
					{
						ClientIpAddress clientIpAddress = new ClientIpAddress
						{
							IpAddress = ipAddress,
							LastSeen = DateTime.UtcNow
						};

						//find location info
						try
						{
							IPAddress ipadr = IPAddress.Parse(ipAddress);

							// check if we are in a dev environment as the client will be the same machine
							if (IPAddress.IsLoopback(ipadr))
							{
								ipadr = IPAddress.Parse("31.14.242.226");
							}

							var cache = this.Settings.Resolve<IPLocation.Caching.LocationCache>();
							var location = await cache.GetLocationAsync(ipadr);

							clientIpAddress.City = location.City.Name;
							clientIpAddress.Region = location.LastSubdivision.Name;
							clientIpAddress.Country = location.Country.Name;
							clientIpAddress.RawIpServiceData = location.Response;
						}
						catch (Exception ex)
						{
							Trace.TraceWarning($"Could not parse IP address {ipAddress}, reason: {ex.Message}.");
						}

						browserSession.IPAddresses.Add(clientIpAddress);
					}
					else
					{
						var ipAddressToBeUpdated = browserSession.IPAddresses.Where(ia => ia.IpAddress == ipAddress).FirstOrDefault();

						if (ipAddressToBeUpdated != null)
							ipAddressToBeUpdated.LastSeen = DateTime.UtcNow;
					}

					await transaction.CommitAsync();
				}
			}

			return browserSession;
		}

		#endregion
	}
}
