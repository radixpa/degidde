
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured 
from django.http import HttpResponseRedirect

from .auth_backends import ModelBackend
from .models import UnconfirmedPropertyError
from .services import UnaccessibleServiceError




class ExternalUserMiddleware(object):
    #def process_request
    # UNFEASIBLE except with a javascript hack!
    #    #log the user in if she has granted access to us with one of the services
    #    #store service data
    
    def process_request(self, request):
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured
        
        # set request attribute of external users, to enable access to 'external properties'
        if user.is_external():
            user.request = request

        if user.aliased_to:
            # Notice the order of saves, which makes retries possible.
            user.save_alias(user.aliased_to)
            user.aliased_to = None
            user.save()

    #    user = request.user
    #    if user.is_validated() and user.is_external():
    #        user.save()
    # set request attribute of external users, to enable access to 'external properties'        

    def process_exception(self, request, exception):
        if isinstance(exception, UnconfirmedPropertyError):
            url = getattr(settings, 'USER_CONFIRM_EXTERNAL_URL', '/accounts/confirm')
            return HttpResponseRedirect(url)

        if isinstance(exception, UnaccessibleServiceError):
            return HttpResponseRedirect(exception.request_access_url) #TODO: consider other possibilities

        # Remember to persist some of the session data after 'confirm' login
