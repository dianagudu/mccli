from flaat import Flaat, tokentools
import json

from .motley_cue_client import get_info, get_authorisation_info, get_local_status


flaat = Flaat()

flaat.set_verbosity(0)
# flaat.set_cache_lifetime(120) # seconds; default is 300

flaat.set_trusted_OP_list([
'https://b2access.eudat.eu/oauth2/',
'https://b2access-integration.fz-juelich.de/oauth2',
'https://unity.helmholtz-data-federation.de/oauth2/',
'https://login.helmholtz-data-federation.de/oauth2/',
'https://login-dev.helmholtz.de/oauth2/',
'https://login.helmholtz.de/oauth2/',
'https://unity.eudat-aai.fz-juelich.de/oauth2/',
'https://services.humanbrainproject.eu/oidc/',
'https://accounts.google.com/',
'https://aai.egi.eu/oidc/',
'https://aai-dev.egi.eu/oidc/',
'https://login.elixir-czech.org/oidc/',
'https://iam-test.indigo-datacloud.eu/',
'https://iam.deep-hybrid-datacloud.eu/',
'https://iam.extreme-datacloud.eu/',
'https://oidc.scc.kit.edu/auth/realms/kit/',
'https://proxy.demo.eduteams.org',
'https://wlcg.cloud.cnaf.infn.it/'
])


def get_all_info(mc_url, token, verify=False):
    if not mc_url and not token:
        return None
    
    info_string = ""
    if mc_url:
        service_info = get_info(mc_url, verify)
        if service_info:
            info_string += "\n==== Information about service ====\n"
            info_string += json.dumps(service_info, indent=2)
            info_string += "\n"
    if mc_url and token:
        authz_info = get_authorisation_info(mc_url, token, verify)
        if authz_info:
            info_string += "\n==== Authorisation on service for provided token issuer (OP) ====\n"
            info_string += json.dumps(authz_info, indent=2)
            info_string += "\n"
        local_status = get_local_status(mc_url, token, verify)
        if local_status:
            info_string += "\n==== Information about your local account on service for provided token ====\n"
            info_string += local_status
            info_string += "\n"
    if token:
        at_info = flaat.get_info_thats_in_at(token)
        info_string += "\n==== Information stored inside the provided Access Token ====\n"
        if at_info:
            info_string += json.dumps(at_info, indent=2)
        else:
            info_string += "Your access token is not a JWT. I.e. it does not contain information (at least I cannot find it.)"
        info_string += "\n"

        user_info = flaat.get_info_from_userinfo_endpoints(token)
        info_string += "\n==== Information retrieved from userinfo endpoint ====\n"
        if user_info:
            info_string += json.dumps(user_info, indent=2)
        else:
            info_string += "The response from the userinfo endpoint does not contain information (at least I cannot find it.)"
        info_string += "\n"

        timeleft = tokentools.get_timeleft(tokentools.merge_tokens([at_info, user_info]))
        if timeleft is not None:
            if timeleft > 0:
                info_string += "\nToken valid for %.1f more seconds." % timeleft
            else:
                info_string += "\nYour token is already EXPIRED for %.1f seconds!" % abs(timeleft)
            info_string += "\n"

    return info_string