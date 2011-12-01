import datetime
import functools
import urllib

from django.core import cache as _cache
from django.utils.encoding import smart_str


FUTURE_DATETIME = datetime.datetime.fromtimestamp(0xffffffff) #Y2106!


def as_base_of(sub):
   return lambda cls: type(
       cls.__name__, (cls,),
       dict(sub.__dict__, 
            __module__=cls.__module__,
            __doc__=cls.__doc__))


def urlquote(s):
    return urllib.quote(smart_str(s))

        
def cache(key_func, timeout=None, namespace=None, 
          _force_set=False, _namespace_sep=':'):
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
