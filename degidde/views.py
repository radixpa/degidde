from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotAllowed

from .services import commit_logout as commit_service_logout, get_logout_urls, \
    is_logged_out, get_service, LOGIN_SERVICE_KEY
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


def service_callback(request, service_name, next_page=None):
    from django.contrib.auth import login, authenticate
    from .auth_backends import ModelBackend as backend
    
    # This must handle csrf and redirect_to.
    # If the user does not grant access, this raises an exception,
    # which will be handled by the middleware.
    service = get_service(service_name).authenticate(request)

    login_service = request.session.get(LOGIN_SERVICE_KEY)
    response = (same_origin_redirect(request, service.redirect_to)
                or HttpResponseRedirect('/')) # hard coded?
    if login_service:
        # TODO: an alias should still be added in case of use of this
        # service for logging in the future.
        return response 
    ext = authenticate(service=service) # Always returns a user
    user = User.fetch_by_alias(ext.id)
    # An aliased user is found when someone logs in externally
    # *for the second time* with the same service.
    if not user and ext.is_validated:
        user = User.fetch_by_email(ext.email)
        if user:
            user.aliased_to = ext.id
        # The new User entity still needs to be validated, but shortcut validation 
        # can be used by accessing the 'login info' as stored in the session.
        # The user must be alerted about the "old" account he's using.
    if user:
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        ext = user
    login(request, ext)
    return response


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


def commit_logout(request, service_name=None):
    from django.contrib.auth import logout

    # TODO: instead of validating csrf token, one must make sure one gets the
    # back the token, used for logging the service auth (e.g. oauth access_token
    # for facebook). This is done by the commit_logout method. 

    if service:
        get_service(service_name)(request).commit_logout()
    # Not passing a service forces the view to log the user out
    lo = False
    if is_logged_out(request) or not service:
        logout(request)
        lo = True
    return _message(SUCCESS, {'logged_out': lo})
