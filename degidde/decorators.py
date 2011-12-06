import functools
import time
import urlparse

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect

from .models import AnonymousUser
from .services import get_service, LOGIN_SERVICE_KEY
from .utils import addr, DEGIDDE


SCOPES = getattr(settings, DEGIDDE, {}).get('SCOPES') or {}
GLOBAL_MAXC, GLOBAL_PERIOD = SCOPES.get("", (60, 60))
#LOGIN_SERVICE_KEY = '_degidde_login_service'
VALIDATE_URL = getattr(settings, 'VALIDATE_URL', '/validate')


# http://codahale.com/a-lesson-in-timing-attacks/
# says "how many of you throttle requests with bad session cookies?"
# Limitting sessions to one IP address may also help.
# http://stackoverflow.com/questions/821870/how-can-i-detect-multiple-logins-into-a-django-web-application-from-different-lo
# http://stackoverflow.com/questions/5055608/django-signals-on-gae-with-django-nonrel
# When a user logs in somewhere else, he should be logged out.
# Trying to login with same username from multiple locations simultaneosly is suspicious behavior.
# Remember throttling password reset link, and other views, besides login.
# What about "rememberme", i.e. session cookies that last indefinitely?
def throttle(function=None, scope=None, _sep='|'):
    from django.core import cache

    # Throttling is done per user, or per IP if the user is anonymous.
    # Due to this, login will effectively have the lowest possible 
    # max rate (*more accurately* changing the session cookie!). 
    # The global max rate is effectively the greatest possible max rate.

    def actual_decorator(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            client_id = user.is_anonymous() and addr(request) or user.id
            t = int(time.time())
            index = (t // period) % 3
            gindex = (t // GLOBAL_PERIOD) % 3           

            if scope:
                key = client_id + _sep + scope + str(index)
            gkey = client_id + _sep + str(index)
            #...
            if exceeded:
                return HttpResponse(status_code=503)
            return view(request, *args, **kwargs)
        return wrapper

    if scope:
        try:
            maxc, period = SCOPES[scope]
        except KeyError:
            raise ValueError("Unknown scope %s" % scope)    
    
    if function:
        return actual_decorator(function)
    return actual_decorator
        

def sensitive(function=None, safe_login=True):
    # In order to be able to use insecure connections, make sure that:
    # (credentials are email and password, but not full_name and username)
    # - users can only input their credentials in pages served securely
    # - users can only send their credentials through secure connections
    # - cookies are never shared between http and https (use different domains)
    # - only public information can be made available through insecure connections
    # Similar to login_required but requires:
    # - a secure connection is being used
    # (if user is authenticated)
    # - user is validated
    # - user is not an invalidatable external user
    # - user is logged in with the (validated) email account or using a password
    # login_required must appear after this decorator

    def actual_decorator(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.is_secure():
                return HttpResponseRedirect(urlparse.urljoin(settings.SECURE_SITE, request.get_full_path()))
        
            user = request.user
            if safe_login and user.is_authenticated():
                if not user.is_validated:
                    return HttpResponseRedirect(VALIDATE_URL)

                # If an external validated user can be tied to a user model with the same email
                #    this will raise an error, since a username will not be available until the 
                # external user becomes tied to a user model. Right after external validated user
                # becomes tied to user model with same email, she'll be invalidated, but 
                # revalidation we'll be easier. Making sure the user is not external prevents
                # information from inadvertedly becoming available to a different user with same
                # email, and also prevents user from becoming invalidated (in a more effective sense).
                user.username
        
                # If user is logged in through unsafe means, the user must log in again.
                # "Logged in login" must be stricter than "non-logged in login".
                login_service = request.session[LOGIN_SERVICE_KEY]
                if login_service and not get_service(login_service).is_email_service:
                    request.user = AnonymousUser()
            return view(request, *args, **kwargs)
        return wrapper  

    if function:
        return actual_decorator(function)
    return actual_decorator

