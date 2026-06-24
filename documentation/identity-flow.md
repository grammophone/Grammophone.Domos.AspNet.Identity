# ASP.NET MVC 5 Identity Flow

`Grammophone.Domos.AspNet.Identity` connects ASP.NET Identity to users stored in a Domos domain container.

The core type is `UserStore<U>`, where `U` derives from `User`. The store expects dependency injection to provide an `IUsersDomainContainer<U>` or richer Domos domain container.

## Store Responsibilities

`UserStore<U>` implements the standard ASP.NET Identity store interfaces for:

- User creation, update and deletion.
- Login providers through Domos `Registration` entities.
- Password hashes.
- Roles through Domos `Role` entities.
- Email and email confirmation.
- Lockout and access-failure counters.
- Two-factor flags.
- Security stamps.

In a music-domain web application, `MusicUser : User` can therefore be used as the ASP.NET Identity user while also being the user type for `MusicSession`, access checking and workflow.

## Events And Listeners

The store exposes events for changes such as creating users, updating users, deleting users, adding logins, removing logins and changing passwords.

Applications that need asynchronous hooks can implement `IUserListener<U>` and register listeners in dependency injection. The store invokes these listener hooks through virtual methods such as `OnCreatingUser`, `OnUpdatingUser` and `OnChangingPassword`.

## Domain Container Lifetime

The store operates through a Domos domain container. A web application should use a request-scoped or otherwise bounded lifetime, matching the lifetime used by its logic sessions.

The store does not replace `LogicSession`. Identity handles authentication and user-account operations. Business operations should still be performed through a session such as `MusicSession` so entity, manager and workflow security are enforced.
