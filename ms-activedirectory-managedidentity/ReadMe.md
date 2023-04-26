---
services: active-directory
platforms: dotnet
author: gljohns
level: 400
client: ASP.NET Web App
service: Azure Key Vault
endpoint: Microsoft identity platform
page_type: sample
languages:
  - csharp  
products:
  - azure
  - azure-active-directory  
  - dotnet
  - managed identity
  - key vault
description: "This sample showcases how to develop a ASP.NET Core MVC web application that gets a secret from a key Vault using Managed Identities."
---
# Acquire a secret from an Azure Key Vault using the Microsoft identity platform

## About this sample

### Overview

This sample showcases how to acquire a secret from an Azure Key Vault using the Microsoft identity platform. It shows you how to use the [managed identity for app service](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity) and acquire a token for an Azure Key Vault resource. 

The sample shows how to use [MSAL.NET (Microsoft Authentication Library)](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet) to obtain an access token for [Azure Key Vault](https://vault.azure.net). Specifically, the sample shows how to retrieve the secret value from a key vault.

Finally, the sample also demonstrates how to use the different [types of managed identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#managed-identity-types) to get an access token.

For more information about how the protocols work in this scenario and other scenarios, see [Authentication Scenarios for Azure AD](http://go.microsoft.com/fwlink/?LinkId=394414).

For more information about Managed Identity, please visit the [Managed Identities for Azure Resources homepage](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

## Topology

<img alt="Overview" src="./images/call-kv.png" />

### Scenario

You want to access an Azure Key Vault secret from a web app. And, you don't want to worry about managing secrets or app credentials.

## How To Run This Sample

To run this sample, you'll need:

- [Visual Studio](https://aka.ms/vsdownload)
- An Internet connection

### Step 1:  Clone or download this repository

From your shell or command line:

```Shell
git clone https://repo link needs to be addedd here 
```

or download and extract the repository .zip file.

> Given that the name of the sample is quiet long, and so are the names of the referenced NuGet packages, you might want to clone it in a folder close to the root of your hard drive, to avoid file size limitations on Windows.

### Step 2:  Modify the Key Vault URI and Secret name values in the code 

Following are the changes you need to make :

- In the [HomeController.cs]() file under the GetSecret method modify the following values, 

    ```cs
        var kvUri = "https://<your-key-vault-name>.vault.azure.net/";
    ```

- also, in the same file in the next line. Provide the secret name you want to query for.

    ```cs
        var secretName = "<secret name>";
    ```
### Step 3:  Build and Publish the sample

Clean the solution, rebuild the solution.

## Publish your web app

To publish your web app, you must first create and configure a new App Service that you can publish your app to.

As part of setting up the App Service, you'll create:

- A new [resource group](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview#terminology) to contain all of the Azure resources for the service.
- A new [Hosting Plan](https://learn.microsoft.com/en-us/azure/app-service/overview-hosting-plans) that specifies the location, size, and features of the web server farm that hosts your app.

Follow these steps to create your App Service resources and publish your project:

1. In **Solution Explorer**, right-click the **ms_activedirectory_managedidentity** project and select **Publish**.
1. In **Publish**, select **Azure** and then **Next**.

> Please refer to the ["Publish your web app"](https://learn.microsoft.com/en-us/azure/app-service/quickstart-dotnetcore?tabs=net60&pivots=development-environment-vs#publish-your-web-app) section for detailed instructions on how to publish this sample to an Azure Web App resource.

## Launch the published web app

Once you launch the web app in the browser, you will see two new menu commands : `Home` and `Get Secret`.


Click on **Read Mail**: the app will show a dump of the last few messages from the current user's inbox, as they are received from the Microsoft Graph.

Click on **View Profile**: the app will show the profile of the current user, as they are received from the Microsoft Graph.

> The sample redeems the Spa Auth Code from the initial token aquisition. You will need to sign-out and sign back in to request the SPA Auth Code.
> If you want to add more client side functionallity, please refer to the [MSAL JS Browser Sample for Hybrid SPA](https://github.com/AzureAD/microsoft-authentication-library-for-js/tree/dev/samples/msal-browser-samples/HybridSample)

Click on **Send Mail**. As it is the first time you do so, you will receive a message informing you that for the app to receive the permissions to send mail as the user, the user needs to grant additional consent. The message offers a link to initiate the process.

![Incremental Consent Link](./ReadmeFiles/IncrementalConsentLink.jpg)

Click it, and you will be transported back to the consent experience, this time it lists just one permission, which is **Send mail as you**.

![Incremental Consent prompt](./ReadmeFiles/Incrementalconsent.JPG)

Once you have consented to this permission, you will be transported back to the application: but this time, you will be presented with a simple experience for authoring an email. Use it to compose and send an email to a mailbox you have access to. Send the message and verify you receive it correctly.

Hit the **sign-out** link on the top right corner.

Sign in again with the same user, and follow the exact same steps described so far. You will notice that the send mail experience appears right away and no longer forces you to grant extra consent, as your decision has been recorded in your previous session.

> Did the sample not work for you as expected? Did you encounter issues trying this sample? Then please reach out to us using the [GitHub Issues](../issues) page.

## About the code

Here there's a quick guide to the most interesting authentication-related bits of the sample.

### Sign in

As it is standard practice for ASP.NET MVC apps, the sign-in functionality is implemented with Microsoft.Identity.Web coordinating the ASP.NET OpenID Connect OWIN middleware and MSAL.NET. Here there's a relevant snippet from the authentication initialization (in the App_Start/Startup.Auth.cs file.):

```CSharp
public void ConfigureAuth(IAppBuilder app)
{
    // ...
    // Get a TokenAcquirerFactory specialized for OWIN
    OwinTokenAcquirerFactory owinTokenAcquirerFactory = TokenAcquirerFactory.GetDefaultInstance<OwinTokenAcquirerFactory>();

    // Configure the web app.
    app.AddMicrosoftIdentityWebApp(owinTokenAcquirerFactory,
                                    updateOptions: options => {});

    // Add the services you need.
    owinTokenAcquirerFactory.Services
            .Configure<ConfidentialClientApplicationOptions>(options => 
                { options.RedirectUri = "https://localhost:44326/"; })
        .AddMicrosoftGraph()
        .AddInMemoryTokenCaches();

    owinTokenAcquirerFactory.Build();
    // ...
}
```

Important things to notice:

- The Authority points to the new authentication endpoint, which supports both personal and work and school accounts.
- the list of scopes includes both entries that are used for the sign-in function (`openid, email, profile`) and for the token acquisition function (`offline_access` is required to obtain refresh_tokens as well; `Mail.Read` is required for getting access tokens that can be used when requesting to read the user's mail).
- In this sample, the issuer validation is turned off, which means that anybody with an account can access the application. Real life applications would likely be more restrictive, limiting access only to those Azure AD tenants or Microsoft accounts associated to customers of the application itself. In other words, real life applications would likely also have a sign-up function - and the sign-in would enforce that only the users who previously signed up have access. For simplicity, this sample does not include sign up features.

### Initial token acquisition

This sample makes use of OpenId Connect hybrid flow, where at authentication time the app receives both sign in info, the  [id_token](https://docs.microsoft.com/azure/active-directory/develop/id-tokens)  and artifacts (in this case, an  [authorization code](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow)) that the app can use for obtaining an [access token](https://docs.microsoft.com/azure/active-directory/develop/access-tokens). This access token can be used to access other resources - in this sample, the Microsoft Graph, for the purpose of reading the user's mailbox.


### Using access tokens in the app, handling token expiration

The `ReadMail` action in the `HomeController` class demonstrates how to take advantage of Microsoft.Identity.Web for calling Microsoft Graph without having to worry about getting a token, or caching it.

Here is the relevant code:

```CSharp
    try
    {
        GraphServiceClient graphServiceClient = this.GetGraphServiceClient();
        await graphServiceClient.Me
            .SendMail(message, true)
            .Request()
            .WithScopes("Mail.Send").PostAsync();
        return View("MailSent");
    }
    catch (ServiceException graphEx) when (graphEx.InnerException is MicrosoftIdentityWebChallengeUserException)
    {
        ChallengeUser(graphEx.InnerException as MicrosoftIdentityWebChallengeUserException);
        return View();
    }
    catch(Exception ex)
    {
        ViewBag.Message = ex.Message;
        return View();
    }
}
```

The idea is simple. The code gets an instance of GraphServiceClient, which already knows how to get a token.
That done, all you need to do is to invoke `WithScopes` on the request, asking for the scopes you need. MSAL will look up the cache and return any cached token, which matches with the requirement. If such access tokens are expired or no suitable access tokens are present, but there is an associated refresh token, MSAL will automatically use that to get a new access token and return it transparently.

In the case in which refresh tokens are not present or they fail to obtain a new access token, MSAL will throw `MsalUiRequiredException`, embedded by Microsoft.Identity.Web into a `MicrosoftIdentityWebChallengeUserException`. That means that in order to obtain the requested token, the user must go through an interactive sign-in experience.

In the case of this sample, the `Mail.Read` permission is obtained as part of the login process - hence we need to trigger a new login; however we can't just redirect the user without warning, as it might be disorienting (what is happening, or why, would not be obvious to the user) and there might still be things they can do with the app that do not entail accessing mail. For that reason, the sample simply signals to the view to show a warning - and to offer a link to an action (`RefreshSession`) that the user can leverage for explicitly initiating the re-authentication process.

### Using Spa Auth Code in the Front End

First, configure a new PublicClientApplication from MSAL.js in your single-page application:

```JS
const msalInstance = new msal.PublicClientApplication({
    auth: {
        clientId: "Enter the Client ID from the Web.Config file",
        redirectUri: "https://localhost:44326/",
        authority: "https://login.microsoftonline.com/organizations/"
    }
})
```

Next, render the code that was acquired server-side, and provide it to the acquireTokenByCode API on the MSAL.js PublicClientApplication instance. Be sure to not include any additional scopes that were not included in the first login request, otherwise the user may be prompted for consent.

```js
    var code = spaCode;
    const scopes = ["user.read"];

    console.log('MSAL: acquireTokenByCode hybrid parameters present');

    var authResult = msalInstance.acquireTokenByCode({
        code,
        scopes
    })
```

Once the Access Token is retrieved using the new MSAL.js `acquireTokenByCode` api, the token is then used to read the user's profile 

```js
function callMSGraph(endpoint, token, callback) {
    const headers = new Headers();
    const bearer = `Bearer ${token}`;
    headers.append("Authorization", bearer);

    const options = {
        method: "GET",
        headers: headers
    };

    console.log('request made to Graph API at: ' + new Date().toString());

    fetch(endpoint, options)
        .then(response => response.json())
        .then(response => callback(response, endpoint))
        .then(result => {
            console.log('Successfully Fetched Data from Graph API:', result);
        })
        .catch(error => console.log(error))
}
```

### Handling incremental consent and OAuth2 code redemption

The `SendMail` action demonstrates how to perform operations that require incremental consent.
Observe the structure of the GET overload of that action. The code follows the same structure as the one you saw in `ReadMail`: the difference is in how `MsalUiRequiredException` is handled.
The application did not ask for `Mail.Send` during sign-in, hence the failure to obtain a token silently could have been caused by the fact that the user did not yet grant consent for the app to use this permission. Instead of triggering a new sign-in as we have done in `ReadMail`, here we can craft a specific authorization request for this permission. 

The call to the utility function `ChallengeUser` does precisely that, leveraging ASP.NET to generate an OAuth2/OpenId Connect request for an authorization code for the Mail.Send permission.

```CSharp
private void ChallengeUser(MicrosoftIdentityWebChallengeUserException exc)
{
    var authenticationProperties = new AuthenticationProperties();
    if (exc.Scopes != null)
    {
        authenticationProperties.Dictionary.Add("scopes", string.Join(" ", exc.Scopes));
    }
    if (!string.IsNullOrEmpty(exc.MsalUiRequiredException.Claims))
    {
        authenticationProperties.Dictionary.Add("claims", exc.MsalUiRequiredException.Claims);
    }
    authenticationProperties.Dictionary.Add("login_hint", (HttpContext.User as ClaimsPrincipal).GetDisplayName());
    authenticationProperties.Dictionary.Add("domain_hint", (HttpContext.User as ClaimsPrincipal).GetDomainHint());

    HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties, OpenIdConnectAuthenticationDefaults.AuthenticationType);
}
```

Note that the custom middleware is provided only as an example, and it has numerous limitations (like a hard dependency on `MSALPerUserMemoryTokenCache`) that limit its applicability outside of this scenario.

## How to deploy this sample to Azure

This project has one WebApp / Web API projects. To deploy them to Azure Web Sites, you'll need, for each one, to:

- create an Azure Web Site
- publish the Web App / Web APIs to the web site, and
- update its client(s) to call the web site instead of IIS Express.

### Create and publish the `openidconnect-v2` to an Azure Web Site

1. Sign in to the [Azure portal](https://portal.azure.com).
1. Click `Create a resource` in the top left-hand corner, select **Web** --> **Web App**, and give your web site a name, for example, `openidconnect-v2-contoso.azurewebsites.net`.
1. Thereafter select the `Subscription`, `Resource Group`, `App service plan and Location`. `OS` will be **Windows** and `Publish` will be **Code**.
1. Click `Create` and wait for the App Service to be created.
1. Once you get the `Deployment succeeded` notification, then click on `Go to resource` to navigate to the newly created App service.
1. Once the web site is created, locate it it in the **Dashboard** and click it to open **App Services** **Overview** screen.
1. From the **Overview** tab of the App Service, download the publish profile by clicking the **Get publish profile** link and save it.  Other deployment mechanisms, such as from source control, can also be used.
1. Switch to Visual Studio and go to the openidconnect-v2 project.  Right click on the project in the Solution Explorer and select **Publish**.  Click **Import Profile** on the bottom bar, and import the publish profile that you downloaded earlier.
1. Click on **Configure** and in the `Connection tab`, update the Destination URL so that it is a `https` in the home page url, for example [https://openidconnect-v2-contoso.azurewebsites.net](https://openidconnect-v2-contoso.azurewebsites.net). Click **Next**.
1. On the Settings tab, make sure `Enable Organizational Authentication` is NOT selected.  Click **Save**. Click on **Publish** on the main screen.
1. Visual Studio will publish the project and automatically open a browser to the URL of the project.  If you see the default web page of the project, the publication was successful.

### Update the Active Directory tenant application registration for `openidconnect-v2`

1. Navigate back to to the [Azure portal](https://portal.azure.com).
In the left-hand navigation pane, select the **Azure Active Directory** service, and then select **App registrations (Preview)**.
1. In the resultant screen, select the `openidconnect-v2` application.
1. From the *Branding* menu, update the **Home page URL**, to the address of your service, for example [https://openidconnect-v2-contoso.azurewebsites.net](https://openidconnect-v2-contoso.azurewebsites.net). Save the configuration.
1. Add the same URL in the list of values of the *Authentication -> Redirect URIs* menu. If you have multiple redirect urls, make sure that there a new entry using the App service's Uri for each redirect url.

## Community Help and Support

Use [Stack Overflow](http://stackoverflow.com/questions/tagged/msal) to get support from the community.
Ask your questions on Stack Overflow first and browse existing issues to see if someone has asked your question before.
Make sure that your questions or comments are tagged with [`msal` `dotnet` `microsoft-graph`].

If you find a bug in the sample, please raise the issue on [GitHub Issues](../../issues).

To provide a recommendation, visit the following [User Voice page](https://feedback.azure.com/forums/169401-azure-active-directory).

## Contributing

If you'd like to contribute to this sample, see [CONTRIBUTING.MD](/CONTRIBUTING.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## More information

For more information, visit the following links:

- [Add sign-in with Microsoft to an ASP.NET web app (V2 endpoint)](https://docs.microsoft.com/azure/active-directory/develop/guidedsetups/active-directory-aspnetwebapp) explains how to re-create the sign-in part of this sample from scratch.
- To learn more about the code, visit [Conceptual documentation for MSAL.NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki#conceptual-documentation) and in particular:

  - [Acquiring tokens with authorization codes on web apps](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Acquiring-tokens-with-authorization-codes-on-web-apps)
  - [Customizing Token cache serialization](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/token-cache-serialization)
  - [Acquiring a token on behalf of a user Service to Services calls](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/on-behalf-of) 

- Articles about the Azure AD V2 endpoint [http://aka.ms/aaddevv2](http://aka.ms/aaddevv2), with a focus on:

  - [Azure Active Directory v2.0 and OAuth 2.0 On-Behalf-Of flow](https://docs.microsoft.com/azure/active-directory/develop/active-directory-v2-protocols-oauth-on-behalf-of)
  - [Incremental and dynamic consent](https://docs.microsoft.com/azure/active-directory/develop/active-directory-v2-compare#incremental-and-dynamic-consent)

- Articles about the Microsoft Graph
  - [Overview of Microsoft Graph](https://developer.microsoft.com/graph/docs/concepts/overview)
  - [Get access tokens to call Microsoft Graph](https://developer.microsoft.com/graph/docs/concepts/auth_overview)
  - [Use the Microsoft Graph API](https://developer.microsoft.com/graph/docs/concepts/use_the_api)
