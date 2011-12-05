import collections
import datetime
import functools
import time
import urllib
import urlparse

from django.utils.encoding import smart_str
from django.http import HttpResponseRedirect


DEGIDDE = "DEGIDDE"
FUTURE_DATETIME = datetime.datetime.fromtimestamp(0xffffffff) #Y2106!


def as_base_of(sub):
   return lambda cls: type(
       cls.__name__, (cls,),
       dict(sub.__dict__, 
            __module__=cls.__module__,
            __doc__=cls.__doc__))


def urlquote(s):
    return urllib.quote(smart_str(s))


def addr(request):
    return request.META.get('HTTP_X_FORWARDED_FOR') or request.META['REMOTE_ADDR']


def same_origin_redirect(request, redirect_to, origin=None):
    if redirect_to is None:
        return
    origin = origin or (request.is_secure() and 'https://' or 'http://') + request.get_host()
    parts = urlparse.urlparse(redirect_to)
    netloc = netloc[1] and netloc[0] + '://' + netloc[1]
    # Serurity: Don't allow redirection to a different host!
    if not (netloc and netloc != origin):
        return HttpResponseRedirect(redirect_to)


def invalid_csrf_token(request, csrf_token):
    from django.middleware.csrf import CsrfViewMiddleware, REASON_BAD_TOKEN, REASON_NO_CSRF_COOKIE
    # TODO: this doesn't handle the the referer check for https.

    if getattr(request, 'csrf_processing_done', False):
        return
    cookie = request.META.get('CSRF_COOKIE')
    if cookie is None:
        return CsrfViewMiddleware()._reject(request, REASON_NO_CSRF_COOKIE)
    if csrf_token != cookie: #TODO: use contant_time_compare in next version of django
        return CsrfViewMiddleware()._reject(request, REASON_BAD_TOKEN)
        

def cache(key_func, timeout=None, namespace=None, 
          _force_set=False, _namespace_sep=':'):
    from django.core import cache as _cache

    _namespace = cache.__module__ + '.' + cache.__name__
    def decorator(func):
        namespace = _namespace + _namespace_sep + namespace or func.__name__
        functools.wraps(func)
        def w(*args, **kwargs):
            try:
                key = namespace + _namespace_sep + key_func(*args, **kwargs)
            except TypeError:
                key = None
            if _force_set or not key:
                data = None
            else:
                data = _cache.get(key)
            if data is None:
                data = func(*args, **kwargs)
                if key:
                    if data is None:
                        _cache.delete(key)
                    else:
                        _cache.set(key, data, timeout)
            return data
        w.invalidate = functools.partial(cache, timeout=timeout, namespace=namespace,
                                         _force_set=True)
        return w
    return decorator


#def is_email(string):
#    from django.core.validators import email_re
#    
#    if u'@' not in string:
#        return False
#
#    m = email_re.match(string) 
#    if not m:
#        parts = string.split(u'@')
#        domain_part = parts[-1]
#        try:
#            parts[-1] = parts[-1].encode('idna')
#        except UnicodeError:
#            return False
#        m = email_re.match(u'@'.join(parts))
#    return bool(m)


class ExpireDict(collections.MutableMapping, dict):
    def __init__(self, it=(), timeout=None):
        dict.__init__(self, it)
        self.timeout = timeout
        self._exp = {}

    __contains__ = dict.__contains__
    __iter__ = dict.__iter__
    __len__ = dict.__len__

    def __getitem__(self, k):
        v = dict.__getitem__(self, k)
        e = self._exp[k]
        if e < time.time():
            dict.pop(self, k, None)
            self._exp.pop(k, None)
            raise KeyError(k)
        return v

    def __setitem__(self, k, v):
        dict.__setitem__(self, k, v)
        self._exp[k] = time.time() + self.timeout
        
    def __delitem__(self, k):
        dict.__delitem__(self, k)
        self._exp.pop(k, None)

    def __repr__(self):
        return "%s(%s, timeout=%r)" % (
            self.__class__.__name__,
            dict.__repr__(self),
            self.timeout)


class Encoder(JSONEncoder):
    def default(self, obj):
        from .models import dump
        try:
            return dump(obj)
        except TypeError:
            pass
        try:
            return obj.dump()
        except AttributeError:
            pass
        try:
            return list(obj)
        except TypeError:
             pass
        return super(Encoder, self).default(obj)
        
