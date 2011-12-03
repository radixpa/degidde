import datetime
import operator

from django.conf import settings
from django.contrib.auth.models import User as _User, UNUSABLE_PASSWORD, AnonymousUser
from django.core.exceptions import ImproperlyConfigured

from .utils import urlquote, cache, FUTURE_DATETIME
from .services import get_service


SUPERUSER_RANKS = ('_superuser',)
STAFF_RANKS = ('_staff',) + SUPERUSER_RANKS
USER_URL_FORMAT = getattr(settings, 'USER_URL_FORMAT', '/users/%s')
USER_CACHE_TIMEOUT = getattr(settings, 'USER_CACHE_TIMEOUT', 0)
USER_CONFIRM_EXTERNAL = getattr(settings, 'USER_CONFIRM_EXTERNAL', False)


_get_full_name = operator.attrgetter('full_name')


def validate_permission(username, group, perm):
    if not (group in getattr(settings, 'USER_GROUPS', ())
        or group in SUPERUSER_RANKS or group in STAFF_RANKS):
        raise ValueError("Invalid group %s" % group)
    if not perm in getattr(settings, 'USER_PERMISSIONS', ()):
        raise ValueError("Invalid permission %s" % perm)


class UserBase(_User):
    def __init__(self, *args, **kwargs):
        email = kwargs.get('email')
        if email:
            self.email = email.strip().lower()
        password = kwargs.get('password')
        if password:
            self.set_password(password)

    @property
    def is_staff(self):
        return self.group in STAFF_RANKS

    @property
    def is_superuser(self):
        return self.group in SUPERUSER_RANKS

    @property
    def is_validated(self):
        return bool(self.date_validated) and self.date_validated < datetime.datetime.now()

    id = property(operator.attrgetter('username'))

    def get_absolute_url(self):
        return USER_URL_FORMAT % urlquote(self.username)

    get_full_name = _get_full_name
    is_external = _User.is_anonymous

    def dump(self):
        r = {'username': self.username, 'email': self.email}
        if self.full_name is not None:
            r['full_name'] = self.full_name
        if self.group is not None:
            r['group'] = self.group
        inactive = not self.is_active
        if inactive:
            r['inactive'] = inactive
        return r

    def validate(self):
        if not self.is_validated():
            self.date_validated = datetime.datetime.now()
        
    def __eq__(self, obj):
        if not isinstance(obj, self.__class__):
            return False
        if self.username:
            return self.username == obj.username
        return self is obj

    def __ne__(self, obj):
        return not self.__eq__(obj)

    def __hash__(self):
        return hash(self.username)

    def get_profile(self):
        raise NotImplementedError
    get_and_delete_messages = get_profile


class Error(Exception):
    pass


class UnconfirmedPropertyError(Error, AttributeError):
    pass


class UsernameTakenError(Error):
    pass


def _external_property(name):
    def getter(self):
        if not hasattr(self, '_user_cache'):
            #optimized for current user, cached in session, etc...
            self._user_cache = self.service.get_user(self.id)
        return self._user_cache.get(name)
    getter.__name__ = name
    return property(getter)


def _unconfirmed_property(name):
    hname = '_' + name
    def getter(self):
        try:
            v = getattr(self, hname)
        except AttributeError:
            raise UnconfirmedPropertyError
        else:
            if v is EXTERNAL:
                return getattr(self, 'external_' + name)
            return v

    def setter(self, value):
        if setter_callback:
            setter_callback(self, value)
        setattr(self, hname, value)

    return property(getter, setter)
        

EXTERNAL = object()


AnonymousUser.group = None
AnonymousUser.is_validated = False
AnonymousUser.is_external = AnonymousUser.is_authenticated
AnonymousUser.validate = AnonymousUser.save
AnonymousUser.aliased_to = None

class ExternalUser(AnonymousUser):
    external_username = _external_property('username')
    external_full_name = _external_property('full_name')
    external_email = _external_property('email')
    if USER_CONFIRM_EXTERNAL:
        username = _unconfirmed_property('username')
        full_name = _unconfirmed_property('full_name')
        email = _unconfirmed_property('email',
                                      lambda s, v: setattr(s, 'is_validated', False))
    else:
        username = external_username
        full_name = external_full_name
        email = external_email
    # this will send confirmation emails if needed!
    is_active = True
    last_login = None
    user = None
    _service = None

    def __init__(self, id): # service handles caching
        # TODO: there must be a way for a user to disallow further logging in
        # through a particular external account
        # Certain actions (like creating an article, and disallowing an ext login) 
        # must only be allowed after authenticating with a password
        self.id = self._id = id

    def __unicode__(self):
        return self._id

    def __eq__(self, obj):
        if not isinstance(obj, self.__class__):
            return False
        return self._id == obj._id

    def __hash__(self):
        return hash(self._id)

    get_full_name = _get_full_name
    is_anonymous = lambda self: False
    is_authenticated = lambda self: True
    is_external = is_authenticated
    email_user = _User.email_user.__func__

    @classmethod
    def fetch(cls, id=None, service=None):
        if not id:
            try:
                id = service.get_user()["id"]
            except AttributeError:
                raise TypeError
 
        u = cls(id)
        if service:
            u._service = service
            if service.is_email_service():
                u.validate()
        return u

    @property
    def service(self):
        if not self._service:
            self._service = get_service(self._id)(self.request)
        return self._service

    if USER_CONFIRM_EXTERNAL: 
        #TODO: handle case in which a user registers more than once,
        #i.e. there is more than one User instance with the same email.
        def save(self):
            # TODO: review all the different cases!
            from .auth_backends import UserBackend
            from .models import User

            # if possible, convert into User
            user = None
            try:
                user = User(username=self.username)
            except AttributeError:
                user = User.fetch_by_alias(self.id)
                # An aliased user is found when someone logs in externally
                # *for the second time* with the same service.
                if not user and self.is_validated:
                    user = User.fetch_by_email(self.email)
                    user.aliased_to = self.id
                # The new User entity still needs to be validated, but shortcut validation 
                # can be used by accessing the 'login info' as stored in the session.
                # The user must be alerted about the "old" account he's using.
                if user:
                    user.last_login = self.last_login
                    self.id = user.id
                    user.save()
            else:
                user.full_name = getattr(self, 'full_name', None)
                user.email = self.email
                user.last_login = self.last_login
                user.aliased_to = self.id
                self.id = user.id
                if self.is_validated:
                    user.validate()
                if not user.save(force_insert=True):
                    raise UsernameTakenError
        
        if user:
            self.user = user #this may be useful...
            self.backend = UserBackend
            return user

        def validate(self):
            self.email = EXTERNAL
            self.is_validated = True

    else:
        save = lambda self: None
    
        def validate(self):
            self.is_validated = True

    def dump(self):
        r = {'username': self.username, 'email': self.email}
        if self.full_name is not None:
            r['full_name'] = self.full_name
        return r 


from importlib import import_module
try:
    modname = conf["MODELS_BACKEND"]
except KeyError:
    raise ImproperlyConfigured #...
models = import_module(modname)

Session = models.Session
User = models.User
Permission = models.Permission
dump = models.dump
