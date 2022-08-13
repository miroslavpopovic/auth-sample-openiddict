using Auth.Extensions;
using Auth.Models;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Pages.Consent;

public class IndexModel : PageModel
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(
        IIdentityServerInteractionService interaction, IEventService events, ILogger<IndexModel> logger)
    {
        _interaction = interaction;
        _events = events;
        _logger = logger;
    }

    [BindProperty]
    public ConsentViewModel? Model { get; set; }

    public string? RedirectUrl { get; set; }

    public async Task<IActionResult> OnGetAsync(string returnUrl)
    {
        Model = await BuildViewModelAsync(returnUrl);

        if (Model == null)
        {
            return RedirectToPage("/Error");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var result = await ProcessConsent(Model);

        if (result.IsRedirect)
        {
            var context = await _interaction.GetAuthorizationContextAsync(Model?.ReturnUrl);

            if (context?.IsNativeClient() == true)
            {
                // The client is native, so this change in how to
                // return the response is for better UX for the end user.
                return this.LoadingPage("/Redirect", result.RedirectUri!);
            }

            return Redirect(result.RedirectUri!);
        }

        if (result.HasValidationError)
        {
            ModelState.AddModelError(string.Empty, result.ValidationError!);
        }

        if (result.ShowView)
        {
            Model = result.ViewModel;
            return Page();
        }

        return RedirectToPage("/Error");
    }

    private async Task<ConsentViewModel?> BuildViewModelAsync(string returnUrl, ConsentInputModel? model = null)
    {
        var request = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if (request != null)
        {
            return CreateConsentViewModel(model, returnUrl, request);
        }
        else
        {
            _logger.LogError("No consent request matching request: {0}", returnUrl);
        }

        return null;
    }

    private static ConsentViewModel CreateConsentViewModel(
        ConsentInputModel? model, string returnUrl, AuthorizationRequest request)
    {
        var vm = new ConsentViewModel
        {
            RememberConsent = model?.RememberConsent ?? true,
            ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),
            Description = model?.Description ?? string.Empty,

            ReturnUrl = returnUrl,

            ClientName = request.Client.ClientName ?? request.Client.ClientId,
            ClientUrl = request.Client.ClientUri,
            ClientLogoUrl = request.Client.LogoUri,
            AllowRememberConsent = request.Client.AllowRememberConsent
        };

        vm.IdentityScopes = request.ValidatedResources.Resources.IdentityResources
            .Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null))
            .ToArray();

        var apiScopes = new List<ScopeViewModel>();
        foreach (var parsedScope in request.ValidatedResources.ParsedScopes)
        {
            var apiScope = request.ValidatedResources.Resources.FindApiScope(parsedScope.ParsedName);
            if (apiScope != null)
            {
                var scopeVm = CreateScopeViewModel(
                    parsedScope, apiScope, vm.ScopesConsented.Contains(parsedScope.RawValue) || model == null);
                apiScopes.Add(scopeVm);
            }
        }

        if (ConsentOptions.EnableOfflineAccess && request.ValidatedResources.Resources.OfflineAccess)
        {
            apiScopes.Add(
                GetOfflineAccessScope(
                    vm.ScopesConsented.Contains(
                        IdentityServerConstants.StandardScopes.OfflineAccess) || model == null));
        }

        vm.ApiScopes = apiScopes;

        return vm;
    }

    private static ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
    {
        return new ScopeViewModel
        {
            Value = identity.Name,
            DisplayName = identity.DisplayName ?? identity.Name,
            Description = identity.Description,
            Emphasize = identity.Emphasize,
            Required = identity.Required,
            Checked = check || identity.Required
        };
    }

    private static ScopeViewModel CreateScopeViewModel(ParsedScopeValue parsedScopeValue, ApiScope apiScope, bool check)
    {
        var displayName = apiScope.DisplayName ?? apiScope.Name;
        if (!string.IsNullOrWhiteSpace(parsedScopeValue.ParsedParameter))
        {
            displayName += $":{parsedScopeValue.ParsedParameter}";
        }

        return new ScopeViewModel
        {
            Value = parsedScopeValue.RawValue,
            DisplayName = displayName,
            Description = apiScope.Description,
            Emphasize = apiScope.Emphasize,
            Required = apiScope.Required,
            Checked = check || apiScope.Required
        };
    }

    private static ScopeViewModel GetOfflineAccessScope(bool check)
    {
        return new ScopeViewModel
        {
            Value = IdentityServerConstants.StandardScopes.OfflineAccess,
            DisplayName = ConsentOptions.OfflineAccessDisplayName,
            Description = ConsentOptions.OfflineAccessDescription,
            Emphasize = true,
            Checked = check
        };
    }

    private async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel? model)
    {
        var result = new ProcessConsentResult();

        // validate return url is still valid
        var request = await _interaction.GetAuthorizationContextAsync(model?.ReturnUrl);
        if (request == null) return result;

        ConsentResponse? grantedConsent = null;

        // user clicked 'no' - send back the standard 'access_denied' response
        if (model?.Button == "no")
        {
            grantedConsent = new ConsentResponse { Error = AuthorizationError.AccessDenied };

            // emit event
            await _events.RaiseAsync(
                new ConsentDeniedEvent(
                    User.GetSubjectId(),
                    request.Client.ClientId,
                    request.ValidatedResources.RawScopeValues));
        }
        // user clicked 'yes' - validate the data
        else if (model?.Button == "yes")
        {
            // if the user consented to some scope, build the response model
            if (model.ScopesConsented != null && model.ScopesConsented.Any())
            {
                var scopes = model.ScopesConsented;

                if (ConsentOptions.EnableOfflineAccess == false)
                {
                    scopes = scopes.Where(
                        x => x != IdentityServerConstants.StandardScopes.OfflineAccess);
                }

                grantedConsent = new ConsentResponse
                {
                    RememberConsent = model.RememberConsent,
                    ScopesValuesConsented = scopes.ToArray(),
                    Description = model.Description
                };

                // emit event
                await _events.RaiseAsync(
                    new ConsentGrantedEvent(
                        User.GetSubjectId(),
                        request.Client.ClientId,
                        request.ValidatedResources.RawScopeValues,
                        grantedConsent.ScopesValuesConsented,
                        grantedConsent.RememberConsent));
            }
            else
            {
                result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;
            }
        }
        else
        {
            result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;
        }

        if (grantedConsent != null)
        {
            // communicate outcome of consent back to IdentityServer
            await _interaction.GrantConsentAsync(request, grantedConsent);

            // indicate that's it ok to redirect back to authorization endpoint
            result.RedirectUri = model?.ReturnUrl;
            result.Client = request.Client;
        }
        else
        {
            // we need to redisplay the consent UI
            result.ViewModel = await BuildViewModelAsync(model?.ReturnUrl!, model);
        }

        return result;
    }
}
