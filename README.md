# Grammophone.Domos.AspNet.Identity

`Grammophone.Domos.AspNet.Identity` adapts Domos users to ASP.NET Identity for ASP.NET MVC 5 and OWIN-based applications.

The package lets a web application use users stored in an `IUsersDomainContainer<U>` as ASP.NET Identity users, while still keeping Domos roles, registrations, browser sessions and security claims in the Domos model.

## Main Features

- `UserStore<U>` implements ASP.NET Identity user, login, password, role, email, lockout, two-factor and security-stamp store interfaces.
- `IdentityUser<U>` and `IdentityRole` adapt Domos `User` and `Role` entities to ASP.NET Identity types.
- `BrowserSessionUserStore` and related classes add browser-session tracking and claims.
- `IUserListener<U>` and store events allow applications to react to identity changes.
- Impersonation helper functions emit and read claims used by Domos impersonation flows.

## Documentation

- [Identity flow](documentation/identity-flow.md)
- [Browser sessions and impersonation](documentation/browser-sessions-and-impersonation.md)
