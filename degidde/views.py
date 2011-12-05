from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotAllowed

from .services import commit_logout as commit_service_logout, get_logout_urls, is_logged_out
from .utils import Encoder, same_origin_redirect, invalid_csrf_token


_MESSAGE_KEY = 'message'
SUCCESS = {_MESSAGE_KEY: 'success'}
ERROR = {_MESSAGE_KEY: 'error'}


def _message(type, data=None):
    return HttpResponse(Encoder.encode(dict(type, data=data)))


# TODO: Oauth token will be handled by a middleware and
# converted into a user instance (which can be Anonymous),
# and CSRF protection will be disabled.
# When used internally, a middleware will handle CSRF token.
# Throttling and CAPTCHA are handled by a decorators.
def form_post(request, form, takes_request=False, commit=True, **kwargs):
    if request.method != "POST":
        return HttpResponseNotAllowed(['POST'])

    if takes_request:
        kwargs['request'] = request

    f = form(data=request.POST, **kwargs)
    if f.is_valid():
        f.save(commit=commit)
        result = None
        if hasattr(f, 'get_result'):
            result = f.get_result()
            if isinstance(result, HttpResponse):
                return result
        return _message(SUCCESS, result)
    return _message(ERROR, f.errors)


form = form_post


def model(request, getter, params=(), **kwargs):
    if request.method != "GET":
        return HttpResponseNotAllowed(['GET'])

    kwargs.update({k:request.GET[k] for k in params if k in request.GET})
    m = getter(**kwargs) #TODO: add some 40x errors
    return HttpResponse(Encoder.encode(m))





def logout(request, next_page=None, redirect_field_name=REDIRECT_FIELD_NAME):
    from django.contrib.auth import logout

    csrf_token = request.GET.get("state") # Hard coded!
    # Handle ?next=... e.g. in case this is used as part of an OAuth service.
    # Don't use next if there is a csrf_token.
    response = (invalid_csrf_token(request, csrf_token) 
                or same_origin_redirect(request, request.GET.get(redirect_field_name))
    if response:
        return response

    if next_page:
        return HttpResponseRedirect(next_page)    

    urls = get_logout_urls()
    if not urls:
        logout(request)
    return _message(SUCCESS, {'logged_out': bool(urls), 'remaining': urls})


def commit_logout(request, service=None):
    from django.contrib.auth import logout

    # TODO: instead of validating csrf token, one must make sure one gets the
    # back the token, used for logging the service auth (e.g. oauth access_token
    # for facebook). This is done y commit_service_logout. 

    if service:
        commit_service_logout(request, service)
    # Not passing a service forces the view to log the user out
    lo = False
    if is_logged_out(request) or not service:
        logout(request)
        lo = True
    return _message(SUCCESS, {'logged_out': lo})
