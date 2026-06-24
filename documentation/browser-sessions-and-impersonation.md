# Browser Sessions And Impersonation

The ASP.NET MVC 5 identity integration includes optional browser-session support.

`BrowserSessionUserStore`, `BrowserSessionUserManager`, `BrowserSessionClaimsIdentityFactory` and `BrowserSessionCookieAuthenticationProvider` cooperate to record browser-session metadata against Domos users.

## Browser Sessions

Browser sessions are Domos entities that can track sign-in time, last-seen time, fingerprint and client IP information. They are useful for security auditing, user-session management and event logging.

In a music-domain portal, browser sessions can show that a `MusicUser` signed in from a particular client before editing albums for a record label.

## Claims

The claims factory emits claims required by ASP.NET Identity and Domos. These can include user identifiers, security stamps and browser-session data.

## Impersonation

`ImpersonationFunctions` and `IdentityClaimNames` define helper conventions for representing impersonation in claims.

Impersonation is still enforced by Domos logic sessions. A support user can carry claims indicating an impersonated `MusicUser`, and the application can create a `LogicSession` or impersonation scope using that information. Security decisions then use the impersonated acting user until the scope ends.
