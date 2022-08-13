using Auth.Models;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Auth.Pages.Device;

public class DeviceAuthorizationPageModel : PageModel
{
    private readonly IDeviceFlowInteractionService _interaction;

    protected DeviceAuthorizationPageModel(IDeviceFlowInteractionService interaction)
    {
        _interaction = interaction;
    }

    protected async Task<DeviceAuthorizationViewModel?> BuildViewModelAsync(
        string userCode, DeviceAuthorizationInputModel? model = null)
    {
        var request = await _interaction.GetAuthorizationContextAsync(userCode);

        if (request != null)
        {
            return CreateConsentViewModel(userCode, model, request);
        }

        return null;
    }

    private DeviceAuthorizationViewModel CreateConsentViewModel(
        string userCode, DeviceAuthorizationInputModel? model, DeviceFlowAuthorizationRequest request)
    {
        var vm = new DeviceAuthorizationViewModel
        {
            UserCode = userCode,
            Description = model?.Description ?? string.Empty,

            RememberConsent = model?.RememberConsent ?? true,
            ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),

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

    private ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
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

    public ScopeViewModel CreateScopeViewModel(ParsedScopeValue parsedScopeValue, ApiScope apiScope, bool check)
    {
        return new ScopeViewModel
        {
            Value = parsedScopeValue.RawValue,
            // todo: use the parsed scope value in the display?
            DisplayName = apiScope.DisplayName ?? apiScope.Name,
            Description = apiScope.Description,
            Emphasize = apiScope.Emphasize,
            Required = apiScope.Required,
            Checked = check || apiScope.Required
        };
    }

    private ScopeViewModel GetOfflineAccessScope(bool check)
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
}
